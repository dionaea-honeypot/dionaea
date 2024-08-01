# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

add_executable(dionaea "")

target_sources(
    dionaea
    PRIVATE
    dionaea.c
    bistream.c
    connection.c
    connection_dtls.c
    connection_tcp.c
    connection_tls.c
    connection_udp.c
    dns.c
    incident.c
    log.c
    modules.c
    node_info.c
    pchild.c
    processor.c
    refcount.c
    signals.c
    ssl.c
    threads.c
    util.c
)

target_include_directories(
    dionaea
    PRIVATE
        ..
        ../include
        ${GLIB2_INCLUDE_DIRS}
        ${GMODULE2_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/..
)

set_target_properties(
    dionaea PROPERTIES
    ENABLE_EXPORTS 1
)

target_link_libraries(
    dionaea
    ${GLIB2_LIBRARIES}
    ${GMODULE2_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    EV::EV
    UDNS::UDNS
)

########### install files ###############

install (
    TARGETS dionaea
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

configure_file(
    ${PROJECT_SOURCE_DIR}/conf/dionaea.cfg.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/conf/dionaea.cfg
    ESCAPE_QUOTES
    @ONLY
)

install_if_not_exists(
    ${CMAKE_CURRENT_BINARY_DIR}/conf/dionaea.cfg
    ${DIONAEA_CONFDIR}
)

install(
    DIRECTORY
    DESTINATION ${DIONAEA_STATEDIR}
)
install(
    DIRECTORY
    DESTINATION ${DIONAEA_STATEDIR}/binaries
)
install(
    DIRECTORY
    DESTINATION ${DIONAEA_STATEDIR}/bistreams
)
install(
    DIRECTORY
    DESTINATION ${DIONAEA_LOGDIR}
)
