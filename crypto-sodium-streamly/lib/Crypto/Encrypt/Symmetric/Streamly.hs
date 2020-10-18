-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}
{-# LANGUAGE TypeFamilies #-}

-- ! This module has the same API as the corresponding strict module.
-- ! So, the docs should be kept more-or-less in sync.

-- | Symmetric authenticated encryption for @streamly@ streams.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Encrypt.Symmetric.Streamly as Symmetric
--
-- encryptedStream = Symmetric.'encrypt' key messageStream
-- decryptedStream = Symmetric.'decrypt' key encryptedStream
-- @
--
-- The functions in this module allow you to encrypt/decrypt a stream
-- of data. The important property is that an encrypted stream is then
-- safe to consume immediately, since each single chunk is encrypted
-- and authenticated individually.
--
-- The size of each chunk, they order, and their number are authenticated
-- too. This has the following implications:
--
-- *   It matters how you split your original data into streamed chunks.
--
-- *   The attacker will not be able to reorder the chunks.
--
-- *   The attacker will not be able to drop any chunks. In particular,
--     they cannot cut your stream short without you noticing.
--
-- This is @crypto_secretstream_xchacha20poly1305@ from libsodium.
-- PUSH and REKEY tags are currently not supported.
module Crypto.Encrypt.Symmetric.Streamly
  (
  -- * Keys
    Key
  , toKey

  -- * Encryption
  , encrypt
  , decrypt

  , DecryptionError (..)
  ) where

import Prelude hiding (length)

import Control.Exception.Safe (Exception, MonadCatch, throwM)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Crypto.Encrypt.Symmetric.Stream (toKey, Key)
import Data.ByteArray (ByteArray, ByteArrayAccess, allocRet, length, withByteArray)
import Foreign.Marshal.Alloc (alloca, free, malloc)
import Foreign.Ptr (nullPtr)
import Foreign.Storable (peek)
import Streamly.Prelude (MonadAsync, SerialT)

import qualified Libsodium as Na
import qualified Streamly.Prelude as S

import Crypto.Streamly.Util (mapLastSpecialM)


-- | Encryption header length.
hlen :: Int
hlen = fromIntegral Na.crypto_secretstream_xchacha20poly1305_headerbytes


-- | Encrypt a stream.
--
-- @
-- encryptedStream = Symmetric.'encrypt' key messageStream
-- @
--
-- *   @key@ is the secret key used for encryption.
--     See "Crypto.Key" in @crypto-sodium@ for how to get one.
--
-- *   @messageStream@ is the data you are encrypting.
--
-- *   Unlike oneshot encryption functions, this one does not need a nonce.
--
-- The encryption protocol prepends a header, so the output stream
-- will have one chunk more than the input stream. The size of this first chunk
-- is Na.'CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES'.
--
-- Each data chunk of the encrypted stream is longer than the corresponding original
-- by Na.'CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES' bytes due to
-- the addition of the authentication information.
--
-- If the input stream is empty, the output stream will be empty too. It will
-- not even contain a header. Empty stream means there are no chunks in it;
-- it is different from a stream containing a single chunk of zero bytes.
--
-- Note: This function is not thread-safe until Sodium is initialised.
-- See "Crypto.Init" in @crypto-sodium@ for details.
encrypt
  ::  forall ctBytes ptBytes keyBytes m.
      ( ByteArrayAccess ptBytes, ByteArray ctBytes
      , ByteArrayAccess keyBytes
      , MonadCatch m, MonadAsync m
      )
  => Key keyBytes  -- ^ Secret key
  -> SerialT m ptBytes  -- ^ Plaintext stream
  -> SerialT m ctBytes
encrypt key stream = S.bracket (liftIO malloc) (liftIO . free) $ \statePtr ->
  let
    header :: m ctBytes
    header = liftIO $ do
      (_ret, h) <-
        allocRet hlen $ \hPtr ->
        withByteArray key $ \keyPtr ->
          Na.crypto_secretstream_xchacha20poly1305_init_push statePtr hPtr keyPtr
      -- _ret can be only 0, so we don’t check it
      pure h

    body :: SerialT m ptBytes -> SerialT m ctBytes
    body = mapLastSpecialM
      (error "Impossible: the empty case is handled elsewhere.")
      encryptChunk

    encryptChunk :: Bool -> ptBytes -> m ctBytes
    encryptChunk isLast chunk = liftIO $ do
      let
        ctLen =
          fromIntegral Na.crypto_secretstream_xchacha20poly1305_abytes + length chunk
        tag =
          if isLast
          then Na.crypto_secretstream_xchacha20poly1305_tag_final
          else Na.crypto_secretstream_xchacha20poly1305_tag_message
      (_ret, ct) <-
        allocRet ctLen $ \ctPtr ->
        withByteArray chunk $ \ptPtr ->
          Na.crypto_secretstream_xchacha20poly1305_push statePtr
            ctPtr nullPtr
            ptPtr (fromIntegral $ length chunk)
            nullPtr 0
            tag
      -- _ret can be only 0, so we don’t check it
      pure ct
  in
  lift (S.null stream) >>= \case
    True -> S.nil
    False -> S.yieldM header <> body stream


-- | Decrypt a stream.
--
-- @
-- decryptedStream = Symmetric.'decrypt' key encryptedStream
-- @
--
-- *   @key@ is the same that was used for encryption.
-- *   @encryptedStream@ is the output of 'encrypt'.
-- *   Unlike oneshot decryption functions, this one does not need a nonce.
--
-- The authenticity of each chunk of the stream is verified the moment this
-- chunk is processed, so it is safe to work with it right away.
--
-- This function will throw 'DecryptionError' if the encrypted stream was
-- corrupted, tampered with, or ends too early.
-- It will also throw this error if extra data remains in the input stream
-- after all encrypted data was read and decrypted.
--
-- Similar to 'encrypt', if the input stream is empty, the output stream
-- will be empty too.
decrypt
  ::  forall ptBytes ctBytes keyBytes m.
      ( ByteArrayAccess keyBytes
      , ByteArray ptBytes, ByteArrayAccess ctBytes
      , MonadCatch m, MonadAsync m
      )
  => Key keyBytes  -- ^ Secret key
  -> SerialT m ctBytes  -- ^ Encrypted stream
  -> SerialT m ptBytes
decrypt key stream' = lift (S.uncons stream') >>= \case
  Nothing -> S.nil
  Just (h, chunks) -> S.bracket (liftIO malloc) (liftIO . free) $ \statePtr ->
    let
      readHeader :: m ()
      readHeader = liftIO $ do
        ret <-
          withByteArray h $ \hPtr ->
          withByteArray key $ \keyPtr ->
            Na.crypto_secretstream_xchacha20poly1305_init_pull statePtr hPtr keyPtr
        if ret == 0
        then pure ()
        else throwM InvalidHeader

      body :: SerialT m ctBytes -> SerialT m ptBytes
      body = mapLastSpecialM (throwM EmptyCyphertext) decryptChunk

      decryptChunk :: Bool -> ctBytes -> m ptBytes
      decryptChunk isLast chunk = liftIO $ do
        let
          ptLen =
            length chunk - fromIntegral Na.crypto_secretstream_xchacha20poly1305_abytes
          tagExpect =
            if isLast
            then Na.crypto_secretstream_xchacha20poly1305_tag_final
            else Na.crypto_secretstream_xchacha20poly1305_tag_message
        ((ret, tagOk), pt) <-
          allocRet ptLen $ \ptPtr ->
          alloca $ \tagPtr ->
          withByteArray chunk $ \ctPtr -> do
            result <- Na.crypto_secretstream_xchacha20poly1305_pull statePtr
              ptPtr nullPtr
              tagPtr
              ctPtr (fromIntegral $ length chunk)
              nullPtr 0
            tagOk' <- (tagExpect ==) <$> peek tagPtr
            pure (result, tagOk')
        if ret == 0 && tagOk
        then pure pt
        else throwM InvalidCyphertext

    in lift readHeader *> body chunks


-- | Exception thrown by 'decrypt'.
data DecryptionError
  = InvalidHeader  -- ^ The header is missing or corrupted.
  | EmptyCyphertext  -- ^ No data followed the header.
  | InvalidCyphertext  -- ^ Corrupted ciphertext.
  deriving (Eq, Show)

instance Exception DecryptionError
