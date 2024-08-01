# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_nfq_SRCS
  nfq.c
)

include_directories (..)
include_directories (../../include)
include_directories (../../src)
include_directories (../../)
include_directories (${GMODULE2_INCLUDE_DIRS})
include_directories (${NFQUEUE_INCLUDE_DIRS})
include_directories (${CMAKE_CURRENT_BINARY_DIR}/../..)

add_library(module_nfq MODULE ${module_nfq_SRCS})

add_dependencies(
  module_nfq
  dionaea
)

set_target_properties(
  module_nfq PROPERTIES
  OUTPUT_NAME nfq
  PREFIX ""
)

target_link_libraries(
  module_nfq
  dionaea
  ${GMODULE2_LIBRARIES}
  ${NFQUEUE_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_nfq
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)
