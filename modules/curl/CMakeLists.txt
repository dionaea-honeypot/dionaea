# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_curl_SRCS
  module.c
)

include_directories (..)
include_directories (../../include)
include_directories (../../src)
include_directories (../../)
include_directories (${GMODULE2_INCLUDE_DIRS})
include_directories (${CMAKE_CURRENT_BINARY_DIR}/../..)

add_library(module_curl MODULE ${module_curl_SRCS})

add_dependencies(
  module_curl
  dionaea
)

set_target_properties(
  module_curl PROPERTIES
  OUTPUT_NAME curl
  PREFIX ""
)

target_link_libraries(
  module_curl
  dionaea
  ${CURL_LIBRARIES}
  ${GMODULE2_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_curl
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)
