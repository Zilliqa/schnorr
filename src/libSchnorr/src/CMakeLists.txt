set(source_files
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
	ECPOINTSerialize.cpp
	SeedPRNG.cpp)

if(NOT ${SCHNORR_BUILD_ARCHIVE})
  add_library (Schnorr SHARED ${source_files})
else()
  add_library (Schnorr STATIC ${source_files})
endif()

if("${OPENSSL_VERSION_MAJOR}.${OPENSSL_VERSION_MINOR}" VERSION_LESS "1.1")
	target_sources (Schnorr PRIVATE generate_dsa_nonce.c)
endif()

target_include_directories (Schnorr PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries (Schnorr OpenSSL::Crypto)
