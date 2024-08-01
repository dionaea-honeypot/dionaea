# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (PYTHONINTERP_FOUND)
    #set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py")
    set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in2")
    set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
    #set(DEPS        "${CMAKE_CURRENT_SOURCE_DIR}/module/__init__.py")
    set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp")
    set(
        DEPS
        ${CMAKE_CURRENT_SOURCE_DIR}/binding.pyx
    )

    configure_file(${SETUP_PY_IN} ${SETUP_PY})

    add_custom_command(
        OUTPUT ${OUTPUT}
        COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
        COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
        DEPENDS ${DEPS}
        #WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_custom_target(
        python_package
        ALL DEPENDS ${OUTPUT}
    )

    #install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --prefix=${CMAKE_INSTALL_PREFIX})")
    install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --install-lib=\$ENV{DESTDIR}/${DIONAEA_PYTHON_SITELIBDIR})")
endif()

add_library(
    module_python MODULE ""
)

set_target_properties(
    module_python PROPERTIES
    OUTPUT_NAME python
    PREFIX ""
)

target_sources(
    module_python
    PRIVATE
        module.c
)

target_include_directories(
    module_python
    PRIVATE
        ..
        ../../include
        ../../
        ${GLIB2_INCLUDE_DIRS}
        ${GMODULE2_INCLUDE_DIRS}
        ${PYTHON_INCLUDE_DIR}
        ${CMAKE_BINARY_DIR}
        #${CMAKE_CURRENT_BINARY_DIR}/../..
)

target_link_libraries(
    module_python
    ${GLIB2_LIBRARY_DIRS}
    ${PYTHON_LIBRARIES}
    dionaea
)

########### install files ###############

install (
    TARGETS module_python
    LIBRARY DESTINATION ${DIONAEA_MODDIR}
)

include(InstallPythonConfig)

########### install service config ###############
install_available_python_config(
    SOURCE_DIR services
    BUILD_DIR services-available
    DESTINATION_DIR services-available
    FILES
        blackhole.yaml
        epmap.yaml
        ftp.yaml.in
        http.yaml.in
        memcache.yaml
        mirror.yaml
        mongo.yaml
        mqtt.yaml
        mssql.yaml
        mysql.yaml
        pptp.yaml
        printer.yaml.in
        sip.yaml.in
        smb.yaml
        tftp.yaml.in
        upnp.yaml.in
)

install_enabled_python_config(
    DESTINATION services-enabled
    SOURCE_REL_DIR ../services-available
    FILES
        blackhole.yaml
        epmap.yaml
        ftp.yaml
        http.yaml
        memcache.yaml
        mirror.yaml
        mongo.yaml
        mqtt.yaml
        mssql.yaml
        mysql.yaml
        pptp.yaml
        printer.yaml
        sip.yaml
        smb.yaml
        tftp.yaml
        upnp.yaml
)

########### install ihandler config ###############
install_available_python_config(
    SOURCE_DIR ihandlers
    BUILD_DIR ihandlers-available
    DESTINATION_DIR ihandlers-available
    FILES
        cmdshell.yaml
        emuprofile.yaml
        emu_scripts.yaml
        fail2ban.yaml.in
        ftp.yaml
        hpfeeds.yaml
        log_db_sql.yaml.in
        log_incident.yaml.in
        log_json.yaml.in
        log_sqlite.yaml.in
        nfq.yaml
        p0f.yaml
        s3.yaml
        store.yaml
        submit_http_post.yaml
        submit_http.yaml
        tftp_download.yaml
        virustotal.yaml.in
)

install_enabled_python_config(
    DESTINATION ihandlers-enabled
    SOURCE_REL_DIR ../ihandlers-available
    FILES
        cmdshell.yaml
        emuprofile.yaml
        ftp.yaml
        log_sqlite.yaml
        store.yaml
        tftp_download.yaml
)

##### IHandler

### fail2ban

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/fail2ban
)

##### Services

### FTP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/ftp/root
)

### HTTP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/http/root
)

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/http/template
)

file(
  GLOB_RECURSE item
  RELATIVE "${PROJECT_SOURCE_DIR}/share/python/http/template"
  "${PROJECT_SOURCE_DIR}/share/python/http/template/*.html.j2"
)

message("${item}")
foreach(filename ${item})
  get_filename_component(FILENAME_PATH ${filename} DIRECTORY)
  install_if_not_exists(
    ${PROJECT_SOURCE_DIR}/share/python/http/template/${filename}
    ${DIONAEA_STATEDIR}/http/template/${FILENAME_PATH}
  )
endforeach()

### PRINTER
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/printer/root
)

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/printer/root/0
)

### SIP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/sip/
)

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/sip/rtp
)

### TFTP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/tftp/root
)

### UPNP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/upnp/root
)
