# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

function(install_if_not_exists src dest)
  set(real_dest "${dest}")
  if(NOT IS_ABSOLUTE "${src}")
    set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  endif()
  get_filename_component(src_name "${src}" NAME)
  get_filename_component(basename_dest "${src}" NAME)
  install(CODE "
    if(\${CMAKE_INSTALL_FULL_PREFIX} MATCHES .*/_CPack_Packages/.* OR NOT EXISTS \"\$ENV{DESTDIR}/${dest}/${src_name}\")
      message(STATUS \"Installing: \$ENV{DESTDIR}/${dest}/${src_name}\")
      execute_process(COMMAND \${CMAKE_COMMAND} -E copy \"${src}\"
                      \"\$ENV{DESTDIR}/${dest}/${src_name}\"
                      RESULT_VARIABLE copy_result
                      ERROR_VARIABLE error_output)
      if(copy_result)
        message(FATAL_ERROR \${error_output})
      endif()
    else()
      message(STATUS \"Skipping  : \$ENV{DESTDIR}/${dest}/${src_name}\")
    endif()
  ")
endfunction()
