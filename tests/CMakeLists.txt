add_executable(dlu_tests test_main.cpp)
target_include_directories(dlu_tests PRIVATE ${CMAKE_SOURCE_DIR}/tests)
target_link_libraries(dlu_tests PRIVATE dlucore)
add_test(NAME dlu_tests COMMAND dlu_tests)
