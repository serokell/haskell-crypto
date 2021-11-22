-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Test.Crypto.Sodium.Pwhash where

import Test.HUnit ((@?=), Assertion)

import Data.ByteArray.Sized (sizedByteArray)
import Data.ByteString (ByteString)
import Data.ByteString.Base16 (decodeBase16)
import Data.Either (fromRight)
import GHC.TypeLits (type (<=), KnownNat)

import qualified Data.ByteString as BS
import qualified Libsodium as Na

import Crypto.Sodium.Pwhash.Internal (Algorithm (..), Params (Params), pwhash)


pwhash_test_vector
  ::  forall n. -- ^ Output length.
      ( KnownNat n
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => ByteString  -- ^ Expected hash.
  -> ByteString  -- ^ Password.
  -> ByteString  -- ^ Salt.
  -> Algorithm  -- ^ Hashing algorithm.
  -> Params  -- ^ Hashing params.
  -> Assertion
pwhash_test_vector hash passwd salt alg params = do
  let hash' = fromRight (error "impossible") . decodeBase16 $ hash
  let passwd' = fromRight (error "impossible") . decodeBase16 $ passwd
  let salt' = fromRight (error "impossible") . decodeBase16 $ salt
  let Just salt'N = sizedByteArray (BS.take 16 salt')  -- Note:
    -- for some reason, the test vectors in the file are 32 bytes long,
    -- while the pwhash function needs a 16-byte salt :/
  let Just hash'N = sizedByteArray @n hash'
  result <- pwhash alg params passwd' salt'N
  result @?= Just hash'N


-- Test vectors from
-- https://github.com/jedisct1/libsodium/blob/f911b56650b680ecfc5d32b11b090849fc2b5f92/test/default/pwhash_argon2id.c

unit_pwhash_argon2id_1 :: Assertion
unit_pwhash_argon2id_1 =
  pwhash_test_vector
    @155
    "18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced615337b9eec6ac4461c6ca07f0939741e57c24d0005c7ea171a0ee1e7348249d135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea47f91f0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534a0700e246a79a49b3f74eb89ec6205fe1eeb941c73b1fcf1"
    (mconcat $
      [ "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0"
      , "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d"
      , "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5"
      , "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6"
      ]
    )
    "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2"
    Argon2id_1_3
    (Params 5 7256678)

unit_pwhash_argon2id_2 :: Assertion
unit_pwhash_argon2id_2 =
  pwhash_test_vector
    @250
    "26bab5f101560e48c711da4f05e81f5a3802b7a93d5155b9cab153069cc42b8e9f910bfead747652a0708d70e4de0bada37218bd203a1201c36b42f9a269b675b1f30cfc36f35a3030e9c7f57dfba0d341a974c1886f708c3e8297efbfe411bb9d51375264bd7c70d57a8a56fc9de2c1c97c08776803ec2cd0140bba8e61dc0f4ad3d3d1a89b4b710af81bfe35a0eea193e18a6da0f5ec05542c9eefc4584458e1da715611ba09617384748bd43b9bf1f3a6df4ecd091d0875e08d6e2fd8a5c7ce08904b5160cd38167b76ec76ef2d310049055a564da23d4ebd2b87e421cc33c401e12d5cd8d936c9baf75ebdfb557d342d2858fc781da31860"
    (mconcat $
      [ "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed"
      , "9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e0"
      , "0cc2890277f0fd3c622115772f7048adaebed86e"
      ]
    )
    "f1192dd5dc2368b9cd421338b22433455ee0a3699f9379a08b9650ea2c126f0d"
    Argon2id_1_3
    (Params 4 7849083)

unit_pwhash_argon2id_3 :: Assertion
unit_pwhash_argon2id_3 =
  pwhash_test_vector
    @249
    "6eb45e668582d63788ca8f6e930ca60b045a795fca987344f9a7a135aa3b5132b50a34a3864c26581f1f56dd0bcbfafbfa92cd9bff6b24a734cfe88f854aef4bda0a7983120f44936e8ff31d29728ac08ccce6f3f916b3c63962755c23a1fa9bb4e8823fc867bfd18f28980d94bc5874423ab7f96cc0ab78d8fa21fbd00cd3a1d96a73fa439ccc3fc4eab1590677b06cc78b0f674dfb680f23022fb902022dd8620803229c6ddf79a8156ccfce48bbd76c05ab670634f206e5b2e896230baa74a856964dbd8511acb71d75a1506766a125d8ce037f1db72086ebc3bccaefbd8cd9380167c2530386544ebfbeadbe237784d102bb92a10fd242"
    (mconcat $
      [ "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6a3"
      , "b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717e392"
      , "be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d295856b0"
      , "441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e4347f491"
      , "5d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b6ca6012746"
      , "711f58c8c392016b2fdfc09c64f0f6b6ab7b"
      ]
    )
    "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194"
    Argon2id_1_3
    (Params 3 7994791)

-- unit_pwhash_argon2id_4 is skipped because it is a test for an incorrect output
-- size, which is impossible due to stronger types in this library

unit_pwhash_argon2id_5 :: Assertion
unit_pwhash_argon2id_5 =
  pwhash_test_vector
    @190
    "08d8cd330c57e1b4643241d05bb468ba4ee4e932cd0858816be9ef15360b27bbd06a87130ee92222be267a29b81f5ae8fe8613324cfc4832dc49387fd0602f1c57b4d0f3855db94fb7e12eb05f9a484aed4a4307abf586cd3d55c809bc081541e00b682772fb2066504ff935b8ebc551a2083882f874bc0fae68e56848ae34c91097c3bf0cca8e75c0797eef3efde3f75e005815018db3cf7c109a812264c4de69dcb22322dbbcfa447f5b00ecd1b04a7be1569c8e556adb7bba48adf81d"
    (mconcat $
      [ "4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82"
      , "ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d"
      , "43ced68642bfb8bbbdd0f50b30118f5e"
      ]
    )
    "39d82eef32010b8b79cc5ba88ed539fbaba741100f2edbeca7cc171ffeabf258"
    Argon2id_1_3
    (Params 3 1432947)

unit_pwhash_argon2id_6 :: Assertion
unit_pwhash_argon2id_6 =
  pwhash_test_vector
    @178
    "d6e9d6cabd42fb9ba7162fe9b8e41d59d3c7034756cb460c9affe393308bd0225ce0371f2e6c3ca32aca2002bf2d3909c6b6e7dfc4a00e850ff4f570f8f749d4bb6f0091e554be67a9095ae1eefaa1a933316cbec3c2fd4a14a5b6941bda9b7eabd821d79abde2475a53af1a8571c7ee46460be415882e0b393f48c12f740a6a72cba9773000602e13b40d3dfa6ac1d4ec43a838b7e3e165fecad4b2498389e60a3ff9f0f8f4b9fca1126e64f49501e38690"
    (mconcat $
      [ "c7b09aec680e7b42fedd7fc792e78b2f6c1bea8f4a884320b648f81e8cf515e8ba"
      , "9dcfb11d43c4aae114c1734aa69ca82d44998365db9c93744fa28b63fd16000e82"
      , "61cbbe083e7e2da1e5f696bde0834fe53146d7e0e35e7de9920d041f5a5621aabe"
      , "02da3e2b09b405b77937efef3197bd5772e41fdb73fb5294478e45208063b5f58e"
      , "089dbeb6d6342a909c1307b3fff5fe2cf4da56bdae50848f"
      ]
    )
    "039c056d933b475032777edbaffac50f143f64c123329ed9cf59e3b65d3f43b6"
    Argon2id_1_3
    (Params 3 4886999)

unit_pwhash_argon2id_7 :: Assertion
unit_pwhash_argon2id_7 =
  pwhash_test_vector
    @231
    "7fb72409b0987f8190c3729710e98c3f80c5a8727d425fdcde7f3644d467fe973f5b5fee683bd3fce812cb9ae5e9921a2d06c2f1905e4e839692f2b934b682f11a2fe2b90482ea5dd234863516dba6f52dc0702d324ec77d860c2e181f84472bd7104fedce071ffa93c5309494ad51623d214447a7b2b1462dc7d5d55a1f6fd5b54ce024118d86f0c6489d16545aaa87b6689dad9f2fb47fda9894f8e12b87d978b483ccd4cc5fd9595cdc7a818452f915ce2f7df95ec12b1c72e3788d473441d884f9748eb14703c21b45d82fd667b85f5b2d98c13303b3fe76285531a826b6fc0fe8e3dddecf"
    (mconcat $
      [ "b540beb016a5366524d4605156493f9874514a5aa58818cd0c6dfffaa9e90205f1"
      , "7b"
      ]
    )
    "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb"
    Argon2id_1_3
    (Params 1 1631659)

unit_pwhash_argon2id_8 :: Assertion
unit_pwhash_argon2id_8 =
  pwhash_test_vector
    @167
    "4e702bc5f891df884c6ddaa243aa846ce3c087fe930fef0f36b3c2be34164ccc295db509254743f18f947159c813bcd5dd8d94a3aec93bbe57605d1fad1aef1112687c3d4ef1cb329d21f1632f626818d766915d886e8d819e4b0b9c9307f4b6afc081e13b0cf31db382ff1bf05a16aac7af696336d75e99f82163e0f371e1d25c4add808e215697ad3f779a51a462f8bf52610af21fc69dba6b072606f2dabca7d4ae1d91d919"
    (mconcat $
      [ "a14975c26c088755a8b715ff2528d647cd343987fcf4aa25e7194a8417fb2b4b3f"
      , "7268da9f3182b4cfb22d138b2749d673a47ecc7525dd15a0a3c66046971784bb63"
      , "d7eae24cc84f2631712075a10e10a96b0e0ee67c43e01c423cb9c44e5371017e9c"
      , "496956b632158da3fe12addecb88912e6759bc37f9af2f45af72c5cae3b179ffb6"
      , "76a697de6ebe45cd4c16d4a9d642d29ddc0186a0a48cb6cd62bfc3dd229d313b30"
      , "1560971e740e2cf1f99a9a090a5b283f35475057e96d7064e2e0fc81984591068d"
      , "55a3b4169f22cccb0745a2689407ea1901a0a766eb99"
      ]
    )
    "3d968b2752b8838431165059319f3ff8910b7b8ecb54ea01d3f54769e9d98daf"
    Argon2id_1_3
    (Params 3 1784128)


-- Test vectors from
-- https://github.com/jedisct1/libsodium/blob/f911b56650b680ecfc5d32b11b090849fc2b5f92/test/default/pwhash_argon2i.c

unit_pwhash_argon2i_1 :: Assertion
unit_pwhash_argon2i_1 =
  pwhash_test_vector
    @155
    "23b803c84eaa25f4b44634cc1e5e37792c53fcd9b1eb20f865329c68e09cbfa9f1968757901b383fce221afe27713f97914a041395bbe1fb70e079e5bed2c7145b1f6154046f5958e9b1b29055454e264d1f2231c316f26be2e3738e83a80315e9a0951ce4b137b52e7d5ee7b37f7d936dcee51362bcf792595e3c896ad5042734fc90c92cae572ce63ff659a2f7974a3bd730d04d525d253ccc38"
    (mconcat $
      [ "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0"
      , "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d"
      , "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5"
      , "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6"
      ]
    )
    "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2"
    Argon2i_1_3
    (Params 5 7256678)

unit_pwhash_argon2i_2 :: Assertion
unit_pwhash_argon2i_2 =
  pwhash_test_vector
    @250
    "0bb3769b064b9c43a9460476ab38c4a9a2470d55d4c992c6e723af895e4c07c09af41f22f90eab583a0c362d177f4677f212482fd145bfb9ac6211635e48461122bb49097b5fb0739d2cd22a39bf03d268e7495d4fd8d710aa156202f0a06e932ff513e6e7c76a4e98b6df5cf922f124791b1076ad904e6897271f5d7d24c5929e2a3b836d0f2f2697c2d758ee79bf1264f3fae65f3744e0f6d7d07ef6e8b35b70c0f88e9036325bfb24ac7f550351486da87aef10d6b0cb77d1cf6e31cf98399c6f241c605c6530dffb4764784f6c0b0bf601d4e4431e8b18dabdc3079c6e264302ade79f61cbd5497c95486340bb891a737223100be0429650"
    (mconcat $
      [ "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed"
      , "9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e0"
      , "0cc2890277f0fd3c622115772f7048adaebed86e"
      ]
    )
    "f1192dd5dc2368b9cd421338b22433455ee0a3699f9379a08b9650ea2c126f0d"
    Argon2i_1_3
    (Params 4 7849083)

unit_pwhash_argon2i_3 :: Assertion
unit_pwhash_argon2i_3 =
  pwhash_test_vector
    @249
    "e9aa073b0b872f15c083d1d7ce52c09f493b827ca78f13a06c1721b45b1e17b24c04e19fe869333135360197a7eb55994fee3e8d9680aedfdf7674f3ad7b84d59d7eab03579ffc10c7093093bc48ec84252aa1b30f40f5e838f1443e15e2772a39f4e774eb052097e8881e94f15457b779fa2af2bbc9a993687657c7704ac8a37c25c1df4289eb4c70da45f2fd46bc0f78259767d3dd478a7c369cf866758bc36d9bd8e2e3c9fb0cf7fd6073ebf630c1f67fa7d303c07da40b36749d157ea37965fef810f2ea05ae6fc7d96a8f3470d73e15b22b42e8d6986dbfe5303256b2b3560372c4452ffb2a04fb7c6691489f70cb46831be0679117f7"
    (mconcat $
      [ "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6a3"
      , "b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717e392"
      , "be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d295856b0"
      , "441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e4347f491"
      , "5d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b6ca6012746"
      , "711f58c8c392016b2fdfc09c64f0f6b6ab7b"
      ]
    )
    "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194"
    Argon2i_1_3
    (Params 3 7994791)

-- unit_pwhash_argon2i_4 is skipped because it is a test for an incorrect output
-- size, which is impossible due to stronger types in this library

unit_pwhash_argon2i_5 :: Assertion
unit_pwhash_argon2i_5 =
  pwhash_test_vector
    @190
    "c121209f0ba70aed93d49200e5dc82cce013cef25ea31e160bf8db3cf448a59d1a56f6c19259e18ea020553cb75781761d112b2d949a297584c65e60df95ad89c4109825a3171dc6f20b1fd6b0cdfd194861bc2b414295bee5c6c52619e544abce7d520659c3d51de2c60e89948d830695ab38dcb75dd7ab06a4770dd4bc7c8f335519e04b038416b1a7dbd25c026786a8105c5ffe7a0931364f0376ae5772be39b51d91d3281464e0f3a128e7155a68e87cf79626ffca0b2a3022fc8420"
    (mconcat $
      [ "4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82"
      , "ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d"
      , "43ced68642bfb8bbbdd0f50b30118f5e"
      ]
    )
    "39d82eef32010b8b79cc5ba88ed539fbaba741100f2edbeca7cc171ffeabf258"
    Argon2i_1_3
    (Params 3 1432947)

unit_pwhash_argon2i_6 :: Assertion
unit_pwhash_argon2i_6 =
  pwhash_test_vector
    @178
    "91c337ce8918a5805a59b00bd1819d3eb4356807cbd2a80b271c4b482dce03f5b02ae4eb831ff668cbb327b93c300b41da4852e5547bea8342d518dd9311aaeb5f90eccf66d548f9275631f0b1fd4b299cec5d2e86a59e55dc7b3afab6204447b21d1ef1da824abaf31a25a0d6135c4fe81d34a06816c8a6eab19141f5687108500f3719a862af8c5fee36e130c69921e11ce83dfc72c5ec3b862c1bccc5fd63ad57f432fbcca6f9e18d5a59015950cdf053"
    (mconcat $
      [ "c7b09aec680e7b42fedd7fc792e78b2f6c1bea8f4a884320b648f81e8cf515e8ba"
      , "9dcfb11d43c4aae114c1734aa69ca82d44998365db9c93744fa28b63fd16000e82"
      , "61cbbe083e7e2da1e5f696bde0834fe53146d7e0e35e7de9920d041f5a5621aabe"
      , "02da3e2b09b405b77937efef3197bd5772e41fdb73fb5294478e45208063b5f58e"
      , "089dbeb6d6342a909c1307b3fff5fe2cf4da56bdae50848f"
      ]
    )
    "039c056d933b475032777edbaffac50f143f64c123329ed9cf59e3b65d3f43b6"
    Argon2i_1_3
    (Params 3 4886999)

-- unit_pwhash_argon2i_7 is skipped because it is a test for an incorrect
-- opslimit.
-- XXX: Maybe we could encode this restriction in types?

unit_pwhash_argon2i_8 :: Assertion
unit_pwhash_argon2i_8 =
  pwhash_test_vector
    @167
    "e942951dfbc2d508294b10f9e97b47d0cd04e668a043cb95679cc1139df7c27cd54367688725be9d069f5704c12223e7e4ca181fbd0bed18bb4634795e545a6c04a7306933a41a794baedbb628d41bc285e0b9084055ae136f6b63624c874f5a1e1d8be7b0b7227a171d2d7ed578d88bfdcf18323198962d0dcad4126fd3f21adeb1e11d66252ea0c58c91696e91031bfdcc2a9dc0e028d17b9705ba2d7bcdcd1e3ba75b4b1fea"
    (mconcat $
      [ "a14975c26c088755a8b715ff2528d647cd343987fcf4aa25e7194a8417fb2b4b3f"
      , "7268da9f3182b4cfb22d138b2749d673a47ecc7525dd15a0a3c66046971784bb63"
      , "d7eae24cc84f2631712075a10e10a96b0e0ee67c43e01c423cb9c44e5371017e9c"
      , "496956b632158da3fe12addecb88912e6759bc37f9af2f45af72c5cae3b179ffb6"
      , "76a697de6ebe45cd4c16d4a9d642d29ddc0186a0a48cb6cd62bfc3dd229d313b30"
      , "1560971e740e2cf1f99a9a090a5b283f35475057e96d7064e2e0fc81984591068d"
      , "55a3b4169f22cccb0745a2689407ea1901a0a766eb99"
      ]
    )
    "3d968b2752b8838431165059319f3ff8910b7b8ecb54ea01d3f54769e9d98daf"
    Argon2i_1_3
    (Params 3 1784128)
