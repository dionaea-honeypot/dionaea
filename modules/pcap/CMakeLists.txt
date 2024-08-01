# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_pcap_SRCS
  pcap.c
)

include_directories (..)
include_directories (../../include)
include_directories (../../)
include_directories(
  ${GMODULE2_INCLUDE_DIRS}
)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/../..)

add_library(
  module_pcap
  MODULE ${module_pcap_SRCS}
)

set_target_properties(
  module_pcap PROPERTIES
  OUTPUT_NAME pcap
  PREFIX ""
)

target_link_libraries(
  module_pcap
  dionaea
  ${GMODULE2_LIBRARIES}
  PCAP::PCAP
)

########### install files ###############

install(
  TARGETS module_pcap
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)
