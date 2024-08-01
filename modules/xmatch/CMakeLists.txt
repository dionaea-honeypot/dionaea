# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_xmatch_SRCS
  module.c
)

include_directories (..)
include_directories (../../include)
include_directories (../../)
include_directories (${GLIB2_INCLUDE_DIRS})
include_directories (${GMODULE2_INCLUDE_DIRS})

link_directories(${GLIB2_LIBRARY_DIRS})
add_library(
  xmatch
  MODULE ${module_xmatch_SRCS}
)
target_link_libraries (xmatch ${GLIB2_LIBRARIES})
target_link_libraries (xmatch ${GMODULE2_LIBRARIES})

########### install files ###############

install(
  TARGETS xmatch
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)
