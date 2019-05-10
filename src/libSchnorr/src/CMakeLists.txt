add_library (Schnorr SHARED
	Schnorr.cpp
	Schnorr_PrivKey.cpp
	Schnorr_PubKey.cpp
	Schnorr_Signature.cpp
	MultiSig.cpp
	MultiSig_CommitSecret.cpp
	MultiSig_CommitPoint.cpp
	MultiSig_CommitPointHash.cpp
	MultiSig_Challenge.cpp
	MultiSig_Response.cpp
	BIGNUMSerialize.cpp
	ECPOINTSerialize.cpp)

if("${OPENSSL_VERSION_MAJOR}.${OPENSSL_VERSION_MINOR}" VERSION_LESS "1.1")
	target_sources (Schnorr PRIVATE generate_dsa_nonce.c)
endif()

target_include_directories (Schnorr PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries (Schnorr OpenSSL::Crypto)
