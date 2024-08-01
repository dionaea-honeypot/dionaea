# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_emu_SRCS
  module.c
  detect.c
  emulate.c
  profile.c
  hooks.c
)

include_directories (..)
include_directories (../../include)
include_directories (../../)
include_directories (${GLIB2_INCLUDE_DIRS})
include_directories (${LIBEMU_INCLUDE_DIR})
include_directories (${CMAKE_CURRENT_BINARY_DIR}/../..)

add_library(module_emu MODULE ${module_emu_SRCS})

add_dependencies(
  module_emu
  dionaea
)

set_target_properties(
  module_emu PROPERTIES
  OUTPUT_NAME emu
  PREFIX ""
)

target_link_libraries(
  module_emu ${LIBEMU_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_emu
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)
