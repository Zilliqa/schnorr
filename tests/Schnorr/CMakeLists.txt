link_directories(${CMAKE_BINARY_DIR}/lib)

add_executable(Test_Schnorr Test_Schnorr.cpp)
target_link_libraries(Test_Schnorr PUBLIC Schnorr Boost::unit_test_framework)
add_test(NAME Test_Schnorr COMMAND Test_Schnorr)

add_executable(Test_MultiSig Test_MultiSig.cpp)
target_link_libraries(Test_MultiSig PUBLIC Schnorr Boost::unit_test_framework)
add_test(NAME Test_MultiSig COMMAND Test_MultiSig)
