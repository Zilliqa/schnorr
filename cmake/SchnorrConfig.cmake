#.rst:
# FindSchnorr
# -------
#
# Find libSchnorr, Schnorr is the crypto library for the Zilliqa core project.
#
# Result variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``SCHNORR_INCLUDE_DIRS``
#   where to find Schnorr.h, etc.
#
# ``SCHNORR_LIBRARIES``
#   the libraries to link against to use libSchnorr.
#
#   that includes libSchnorr library files.
# ``SCHNORR_FOUND``
#
#   If false, do not try to use SCHNORR.
include(FindPackageHandleStandardArgs)
find_path(SCHNORR_INCLUDE_DIR 
         libSchnorr/include/MultiSig.h
         libSchnorr/include/Schnorr.h
)

find_library(SCHNORR_LIBRARY
            NAMES libSchnorr)

find_package_handle_standard_args(SCHNORR  DEFAULT_MSG
            SCHNORR_INCLUDE_DIR SCHNORR_LIBRARY)

mark_as_advanced(SCHNORR_INCLUDE_DIR SCHNORR_LIBRARY)
set(SCHNORR_LIBRARIES ${SCHNORR_LIBRARY})
set(SCHNORR_INCLUDE_DIRS ${SCHNORR_INCLUDE_DIR})
