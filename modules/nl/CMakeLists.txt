# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_nl_SRCS
  module.c
)

include_directories(..)
include_directories(../../include)
include_directories(../../)
include_directories(
  ${GMODULE2_INCLUDE_DIRS}
  ${LIBNL3_INCLUDE_DIRS}
  ${LIBNL3_ROUTE_INCLUDE_DIRS}
)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/../..)

add_library(
  module_nl
  MODULE ${module_nl_SRCS}
)

set_target_properties(
  module_nl PROPERTIES
  OUTPUT_NAME nl
  PREFIX ""
)

target_link_libraries(
  module_nl
  dionaea
  ${GMODULE2_LIBRARIES}
  ${LIBNL3_LIBRARIES}
  ${LIBNL3_ROUTE_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_nl
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)
