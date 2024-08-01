# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    if(NOT DEFINED WITH_IN_SOURCE_BUILD)
        message(FATAL_ERROR
                "In-source build detected. It is not allowed to build out-of-source!"
                "\n Remove \"${CMAKE_SOURCE_DIR}/CMakeCache.txt\" and try again from another folder, e.g.:"
                "\n "
                "\n rm CMakeCache.txt"
                "\n mkdir build"
                "\n cd build"
                "\n cmake .."
                "\n "
                "\n Alternately define WITH_IN_SOURCE_BUILD to force this option (not recommended!)"
                )
    endif()
endif()

cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

project(
    dionaea
    VERSION 0.11.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# ToDo: move to source file?
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Hide messages from Check*.cmake (e.g. CheckCSourceCompiles)
if(NOT VERBOSE)
    set(CMAKE_REQUIRED_QUIET ON)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(
        CMAKE_BUILD_TYPE Debug
        CACHE STRING "Choose the type of build, options are: None Debug Release"
        FORCE
    )
endif()

string( TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_TOLOWER )
if(CMAKE_BUILD_TYPE_TOLOWER MATCHES debug)
    set(DEBUG_BUILD_TYPE ON)
    add_definitions(-Wall)
    #    add_definitions(-Wall -Wextra)
endif()

option(VERBOSE "Enable verbose output?" OFF)
option(WITH_MODULE_CURL "Build the curl module" ON)
option(WITH_MODULE_EMU "Build the emu module" ON)
#option(WITH_MODULE_NC "Build the nc module" OFF)
option(WITH_MODULE_NFQ "Build the nfq module" ON)
option(WITH_MODULE_NL "Build the nl module" OFF)
option(WITH_MODULE_PCAP "Build the pcap module" ON)
#option(WITH_MODULE_XMATCH "Build the xmatch module" OFF)

option(RELEASE_BUILD "Remove Git revision from program version (use for stable releases)" OFF)

# Default install prefix for Dionaea
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    message(STATUS "INFO: Setting the CMAKE_INSTALL_PREFIX to default - /opt/dionaea")
    set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE "/opt/dionaea")
endif()

message(STATUS "Before GNUInstallDirs: CMAKE_INSTALL_FULL_LOCALSTATEDIR = ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}")
include(GNUInstallDirs)
message(STATUS "After GNUInstallDirs: CMAKE_INSTALL_FULL_LOCALSTATEDIR = ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}")

### Dionaea non-FHS compliant defaults /opt/dionaea
# Dionaea defaults are different from FHS as used in GNUInstallDirs
# for example the default when prefix is set to /opt/dionaea, the configuration
# is expected in /opt/dionaea/etc and not in /etc/opt/dionaea, same for the state dirs
# expected to be in /opt/dionaea/var/lib and not in /var/opt/dionaea/lib
if(CMAKE_INSTALL_PREFIX STREQUAL "/opt/dionaea")
    set(CMAKE_INSTALL_FULL_SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc" CACHE PATH "Configuration")
    set(CMAKE_INSTALL_FULL_LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var" CACHE PATH "Modifiable single-machine data (var)" FORCE)
    set(CMAKE_INSTALL_FULL_RUNSTATEDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run" CACHE PATH "Run-time variable data (LOCALSTATEDIR/run)")
endif()

include(InstallConfig)
include(Packaging)

# Set default version
set(DIONAEA_VERSION ${PROJECT_VERSION})
if(NOT RELEASE_BUILD AND EXISTS ${PROJECT_SOURCE_DIR}/.git)
    find_package(Git)
    if(GIT_FOUND)
        exec_program(
            ${GIT_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}
            ARGS "describe --tag --dirty=-dev"
            OUTPUT_VARIABLE DIONAEA_VERSION
            RETURN_VALUE TAG_RESULT
        )
    else()
        message(STATUS "Git revision could not be determined")
        set(DIONAEA_REVISION "${PROJECT_VERSION}-dev-build")
    endif()
endif()

set(DIONAEA_USER "dionaea" CACHE STRING "Dionaea user")
set(DIONAEA_GROUP "dionaea" CACHE STRING "Dionaea group")
set(DIONAEA_MODDIR ${CMAKE_INSTALL_FULL_LIBDIR}/dionaea CACHE PATH "Dionaea directory for plugin modules")
set(DIONAEA_CONFDIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/dionaea CACHE PATH "Dionaea configuration directory")
set(DIONAEA_RUNDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run" CACHE PATH "Dionaea /run directory")
set(DIONAEA_STATEDIR ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/dionaea CACHE PATH "Dionaea directory for storing the status")
set(DIONAEA_LOGDIR ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/dionaea CACHE PATH "Dionaea log directory")
set(DIONAEA_PYTHON_SITELIBDIR ${CMAKE_INSTALL_FULL_LIBDIR}/dionaea/python CACHE PATH "Dionaea location of python modules")

########### requirements ###############

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.30)
pkg_check_modules(GMODULE2 REQUIRED gmodule-2.0>=2.30)

pkg_check_modules(LIBEMU libemu)
pkg_check_modules(NFQUEUE libnetfilter_queue)
pkg_check_modules(LIBNL3 libnl-3.0)
pkg_check_modules(LIBNL3_ROUTE libnl-route-3.0)

set(Python_ADDITIONAL_VERSIONS 3.4 3.5 3.6 3.7 3.8)
find_package(PythonInterp REQUIRED)
find_package(PythonLibs ${PYTHON_VERSION_STRING} REQUIRED)
find_package(OpenSSL REQUIRED)

find_package(UDNS REQUIRED)
find_package(EV REQUIRED)
find_package(CURL)
find_package(PCAP)

include(CheckIncludeFile)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    check_include_file(linux/sockios.h HAVE_LINUX_SOCKIOS_H)
endif()

include(CheckCSourceRuns)
include(CheckIPv4MappedIPv6)

configure_file(config.h.cmake ${CMAKE_BINARY_DIR}/config.h ESCAPE_QUOTES)
include_directories(${CMAKE_BINARY_DIR})

add_subdirectory(modules)
add_subdirectory(src)

########### install files ###############

install(
    FILES
        CHANGELOG.rst
        CONTRIBUTING.rst
        LICENSE
        README.md
        src/LICENSE.openssl
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)
