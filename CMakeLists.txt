cmake_minimum_required(VERSION 3.16)
project(groupfinder VERSION 1.4.1 LANGUAGES C CXX)

# TeamSpeak 3 ships Qt 5.15.2 built with MSVC 2019 (x64). The plugin must link against the same
# Qt (import libs from Qt 5.15.2 msvc2019_64) and be built in Release so it binds to Qt5Core.dll,
# not Qt5Cored.dll. Never ship Qt DLLs: TS3 already has them.
if(NOT MSVC)
  message(FATAL_ERROR "Build with MSVC: TS3's Qt is MSVC-built, MinGW cannot link against it.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt5 5.15 REQUIRED COMPONENTS Core Gui Widgets)

# Pure logic (Qt Core only) — shared by the plugin and the unit tests.
set(GF_LOGIC_SOURCES
  src/meetings/schedule.cpp
  src/meetings/meeting.cpp
  src/meetings/firing.cpp
  src/query/groupquery.cpp
)

# Qt/TS3-facing meeting code.
set(GF_MEETING_SOURCES
  src/meetings/gf_meetings.cpp
  src/common/ts3api.cpp
  src/common/windowutil.cpp
  src/query/gf_query.cpp
  src/query/querycontroller.cpp
  src/query/groupchecklist.cpp
  src/query/finderwindow.cpp
  src/query/alarmwindow.cpp
  src/meetings/meetingcontroller.cpp
  src/meetings/meetingdialog.cpp
  src/meetings/schedulerwindow.cpp
  src/meetings/warnpopup.cpp
)

add_library(groupfinder SHARED
  src/plugin.c
  ${GF_LOGIC_SOURCES}
  ${GF_MEETING_SOURCES}
)
set_target_properties(groupfinder PROPERTIES PREFIX "" OUTPUT_NAME "groupfinder")
target_include_directories(groupfinder PRIVATE include src)
target_compile_definitions(groupfinder PRIVATE
  GF_VERSION="${PROJECT_VERSION}"
  _CRT_SECURE_NO_WARNINGS
  NOMINMAX
  WIN32
)
target_compile_options(groupfinder PRIVATE /utf-8 /W3)
target_link_libraries(groupfinder PRIVATE Qt5::Core Qt5::Gui Qt5::Widgets)

# Qt 5.15's qvector.h uses stdext::checked_array_iterator, which MSVC 17.8+ flags as deprecated (STL4043).
add_compile_definitions(_SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING)

option(GF_BUILD_TESTS "Build unit tests and the plugin harness" OFF)
if(GF_BUILD_TESTS)
  enable_testing()
  find_package(Qt5 5.15 REQUIRED COMPONENTS Test)

  add_executable(gf_tests
    tests/test_main.cpp
    tests/test_schedule.cpp
    tests/test_meeting.cpp
    tests/test_firing.cpp
    tests/test_groupquery.cpp
    ${GF_LOGIC_SOURCES}
  )
  target_include_directories(gf_tests PRIVATE src tests)
  target_compile_options(gf_tests PRIVATE /utf-8 /W3)
  target_link_libraries(gf_tests PRIVATE Qt5::Core Qt5::Test)
  add_test(NAME gf_tests COMMAND gf_tests)

  # Loads groupfinder.dll with a fake TeamSpeak function table (see tests/plugin_harness.cpp).
  add_executable(gf_harness tests/plugin_harness.cpp ${GF_LOGIC_SOURCES})
  target_include_directories(gf_harness PRIVATE include src)
  target_compile_definitions(gf_harness PRIVATE _CRT_SECURE_NO_WARNINGS WIN32 NOMINMAX)
  target_compile_options(gf_harness PRIVATE /utf-8 /W3)
  target_link_libraries(gf_harness PRIVATE Qt5::Core Qt5::Gui Qt5::Widgets)
  add_dependencies(gf_harness groupfinder)
  # Same asset layout as an installed plugin: <dir>/groupfinder.dll + <dir>/groupfinder/sound/default.wav
  add_custom_command(TARGET gf_harness POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/groupfinder/plugins/groupfinder/sound/default.wav
            $<TARGET_FILE_DIR:groupfinder>/groupfinder/sound/default.wav)
endif()
