include(FindProtobuf)

set(LIB_PROTOBUF_MUTATOR_TARGET external.libprotobuf-mutator)
set(LIB_PROTOBUF_MUTATOR_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${LIB_PROTOBUF_MUTATOR_TARGET})
set(LIB_PROTOBUF_MUTATOR_INCLUDE_DIR ${LIB_PROTOBUF_MUTATOR_INSTALL_DIR}/include/libprotobuf-mutator)

if(${LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF})
    # Get protobuf_generate_cpp from FindProtobuf and override the rest with ExternalProject version.

    set(PROTOBUF_INSTALL_DIR ${LIB_PROTOBUF_MUTATOR_INSTALL_DIR}/src/${LIB_PROTOBUF_MUTATOR_TARGET}-build/external.protobuf)

    IF(CMAKE_BUILD_TYPE MATCHES Debug)
      set(PROTOBUF_LIBRARIES protobufd)
    ELSE()
      set(PROTOBUF_LIBRARIES protobuf)
    ENDIF()

    # List all dependencies of libprotobuf-mutator (protobuf, absl, utf8)
    list(APPEND PROTOBUF_LIBRARIES
      absl_bad_any_cast_impl
      absl_bad_optional_access
      absl_bad_variant_access
      absl_base
      absl_city
      absl_civil_time
      absl_cord
      absl_cord_internal
      absl_cordz_functions
      absl_cordz_handle
      absl_cordz_info
      absl_cordz_sample_token
      absl_crc_cord_state
      absl_crc_cpu_detect
      absl_crc_internal
      absl_crc32c
      absl_debugging_internal
      absl_demangle_internal
      absl_die_if_null
      absl_examine_stack
      absl_exponential_biased
      absl_failure_signal_handler
      absl_flags
      absl_flags_commandlineflag
      absl_flags_commandlineflag_internal
      absl_flags_config
      absl_flags_internal
      absl_flags_marshalling
      absl_flags_parse
      absl_flags_private_handle_accessor
      absl_flags_program_name
      absl_flags_reflection
      absl_flags_usage
      absl_flags_usage_internal
      absl_graphcycles_internal
      absl_hash
      absl_hashtablez_sampler
      absl_int128
      absl_leak_check
      absl_log_entry
      absl_log_flags
      absl_log_globals
      absl_log_initialize
      absl_log_internal_check_op
      absl_log_internal_conditions
      absl_log_internal_format
      absl_log_internal_globals
      absl_log_internal_log_sink_set
      absl_log_internal_message
      absl_log_internal_nullguard
      absl_log_internal_proto
      absl_log_severity
      absl_log_sink
      absl_low_level_hash
      absl_malloc_internal
      absl_periodic_sampler
      absl_random_distributions
      absl_random_internal_distribution_test_util
      absl_random_internal_platform
      absl_random_internal_pool_urbg
      absl_random_internal_randen
      absl_random_internal_randen_hwaes
      absl_random_internal_randen_hwaes_impl
      absl_random_internal_randen_slow
      absl_random_internal_seed_material
      absl_random_seed_gen_exception
      absl_random_seed_sequences
      absl_raw_hash_set
      absl_raw_logging_internal
      absl_scoped_set_env
      absl_spinlock_wait
      absl_stacktrace
      absl_status
      absl_statusor
      absl_str_format_internal
      absl_strerror
      absl_strings
      absl_strings_internal
      absl_symbolize
      absl_synchronization
      absl_throw_delegate
      absl_time
      absl_time_zone
      utf8_validity
    )

    foreach(lib ${PROTOBUF_LIBRARIES})
      set(LIB_PATH ${PROTOBUF_INSTALL_DIR}/lib/lib${lib}.a)
      list(APPEND LIB_PROTOBUF_MUTATOR_BUILD_BYPRODUCTS ${LIB_PATH})

      add_library(${lib} STATIC IMPORTED)
      set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
                   ${LIB_PATH})
      add_dependencies(${lib} ${LIB_PROTOBUF_MUTATOR_TARGET})
    endforeach(lib)

    set(PROTOBUF_INCLUDE_DIR ${PROTOBUF_INSTALL_DIR}/include)
    set(Protobuf_INCLUDE_DIR ${PROTOBUF_INCLUDE_DIR})

    set(Protobuf_LIBRARIES "$<LINK_GROUP:RESCAN,${PROTOBUF_LIBRARIES}>")

    set(PROTOBUF_PROTOC_EXECUTABLE ${PROTOBUF_INSTALL_DIR}/bin/protoc)
    list(APPEND LIB_PROTOBUF_MUTATOR_BUILD_BYPRODUCTS ${PROTOBUF_PROTOC_EXECUTABLE})
    set(Protobuf_PROTOC_EXECUTABLE ${PROTOBUF_PROTOC_EXECUTABLE})

    if(${CMAKE_VERSION} VERSION_LESS "3.10.0")
      set(PROTOBUF_PROTOC_TARGET protoc)
    else()
      set(PROTOBUF_PROTOC_TARGET protobuf::protoc)
    endif()

    if(NOT TARGET ${PROTOBUF_PROTOC_TARGET})
      add_executable(${PROTOBUF_PROTOC_TARGET} IMPORTED)
    endif()

    set_property(TARGET ${PROTOBUF_PROTOC_TARGET} PROPERTY IMPORTED_LOCATION
                 ${PROTOBUF_PROTOC_EXECUTABLE})
endif()

set(LIB_PROTOBUF_MUTATOR_LIBRARIES
  protobuf-mutator
  protobuf-mutator-libfuzzer
)

set(Lib_Protobuf_Mutator_LIBRARIES "$<LINK_GROUP:RESCAN,${LIB_PROTOBUF_MUTATOR_LIBRARIES}>")

foreach(lib ${LIB_PROTOBUF_MUTATOR_LIBRARIES})
  set(LIB_PATH ${LIB_PROTOBUF_MUTATOR_INSTALL_DIR}/lib/lib${lib}.a)
  list(APPEND LIB_PROTOBUF_MUTATOR_BUILD_BYPRODUCTS ${LIB_PATH})

  add_library(${lib} STATIC IMPORTED)
  set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
               ${LIB_PATH})
  add_dependencies(${lib} ${LIB_PROTOBUF_MUTATOR_TARGET})
endforeach(lib)

# Build libprotobuf-mutator and its dependencies (protobuf, absl, utf8) from source
include(ExternalProject)
ExternalProject_Add(${LIB_PROTOBUF_MUTATOR_TARGET}
    PREFIX ${LIB_PROTOBUF_MUTATOR_TARGET}
    GIT_REPOSITORY https://github.com/CodeIntelligenceTesting/libprotobuf-mutator.git
    GIT_SHALLOW TRUE
    GIT_TAG cpp17
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ${CMAKE_COMMAND} <SOURCE_DIR>
      -G${CMAKE_GENERATOR}
      -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
      -DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}
      -DCMAKE_C_COMPILER_LAUNCHER:FILEPATH=${CMAKE_C_COMPILER_LAUNCHER}
      -DCMAKE_CXX_COMPILER_LAUNCHER:FILEPATH=${CMAKE_CXX_COMPILER_LAUNCHER}
      -DCMAKE_C_FLAGS=${PROTOBUF_CFLAGS}
      -DCMAKE_CXX_FLAGS=${PROTOBUF_CXXFLAGS}
      -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
      -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=${LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF}
      -DLIB_PROTO_MUTATOR_TESTING=OFF
    BUILD_BYPRODUCTS ${LIB_PROTOBUF_MUTATOR_BUILD_BYPRODUCTS}
)
