#!/bin/bash

EINVAL=22

THIS_SCRIPT_NAME=$(basename "$0")

function log_info
{
	echo "$THIS_SCRIPT_NAME: $@"
}

function log_warning
{
	echo "$THIS_SCRIPT_NAME: warning: $@"
}

function log_error
{
	echo "$THIS_SCRIPT_NAME: error: $@"
}

function print_help
{
	cat <<-ENDHELP
$THIS_SCRIPT_NAME: options...
\toptions:
\t\t--map=*path where to put SnapAPI System.map file*
\t\t--kver=*kernel version to build SnapAPI for*
\t\t--buildsystem -- indicate that we are building SnapAPI on Cyberprotect buildsystem
ENDHELP
}

IS_BUILDSYSTEM_BUILD=false

for argument in "$@"; do
	case "$argument" in
		--map=*)
			TARGET_SYSTEM_MAP_PATH="${argument#*=}"
			;;

		--kver=*)
			KERNEL_VERSION="${argument#*=}"
			;;

		--buildsystem)
			IS_BUILDSYSTEM_BUILD=true
			;;

		--kernel_src_dir=*)
			KERNEL_SRC_DIR="${argument#*=}"
			;;

		*)
			log_error "'$argument' is not a valid argument"
			print_help
			exit $EINVAL
	esac
done

if [ -z "$KERNEL_VERSION" ]; then
	KERNEL_VERSION="$(uname -r)"
fi

if [ -z "$TARGET_SYSTEM_MAP_PATH" ]; then
	log_error "no System.map file path provided"
	exit $EINVAL
fi

OUTPUT_FILE=kernel_config.h
SYSTEM_MAP_DIRS=(${KERNEL_SRC_DIR} /lib/modules/${KERNEL_VERSION}/ /usr/lib/debug/boot/ /boot/)
ACRONIS_SYSTEM_MAPS_DIR=/usr/lib/Acronis/SnapAPIFiles/SystemMaps/
SYSTEM_MAP_MINSIZE=1000

function find_system_map()
{
	local dir=$1
	log_info "Seek System.map in '${dir}'"

	if [ -e $dir/System.map-${KERNEL_VERSION} ] ;then
		log_info "Found System.map-${KERNEL_VERSION} in '${dir}'"
		SYSTEM_MAP_FILE_TMP=$dir/System.map-${KERNEL_VERSION}

	elif [ -e $dir/System.map ] ;then
		log_info "Found System.map in '${dir}'"

		SYSTEM_MAP_FILE_TMP=$dir/System.map
	fi

	if [ ! -z ${SYSTEM_MAP_FILE_TMP} ]; then
		size=$(stat -c%s "${SYSTEM_MAP_FILE_TMP}")
		if (( $size > ${SYSTEM_MAP_MINSIZE} )); then
			SYSTEM_MAP_FILE=${SYSTEM_MAP_FILE_TMP}
		fi
	fi
}

function get_acronis_system_map
{
	boot_cfg_md5=( $(md5sum /boot/config-${KERNEL_VERSION}) )
	if [ -e ${ACRONIS_SYSTEM_MAPS_DIR}/System.map-${KERNEL_VERSION}-$boot_cfg_md5 ]; then
		SYSTEM_MAP_FILE=${ACRONIS_SYSTEM_MAPS_DIR}/System.map-${KERNEL_VERSION}-$boot_cfg_md5
	fi
}

function generate_acronis_system_map
{
	if [ "$KERNEL_VERSION" != "$(uname -r)" ]; then
		log_error "SnapAPI System.map can be only generated for running kernel"
		if [ "$IS_BUILDSYSTEM_BUILD" == false ]; then
			exit $EINVAL
		fi
	fi

	cat /proc/kallsyms | grep -e ' A \| B \| C \| D \| R \| T \| V \| W \| a ' > \
		"$TARGET_SYSTEM_MAP_PATH"
}

for i in "${SYSTEM_MAP_DIRS[@]}"; do
	find_system_map $i
	if [ ! -z ${SYSTEM_MAP_FILE} ]; then
		break
	fi
done

if [  -z ${SYSTEM_MAP_FILE} ]; then
	get_acronis_system_map
fi

if [ ! -z "${SYSTEM_MAP_FILE}" ]; then
	cp "${SYSTEM_MAP_FILE}" "${TARGET_SYSTEM_MAP_PATH}"
else
	log_info "System.map file not found, generating it from /proc/kallsyms"
	generate_acronis_system_map
fi

rm -f ${OUTPUT_FILE}
log_info "Generate \"${OUTPUT_FILE}\" for kernel \"${KERNEL_VERSION}\" and system map \"${SYSTEM_MAP_FILE}\"."

echo "#ifndef SNAPAPI_KERNEL_CONFIG" >> "${OUTPUT_FILE}"
echo "#define SNAPAPI_KERNEL_CONFIG" >> "${OUTPUT_FILE}"
if [ $IS_BUILDSYSTEM_BUILD == false ] || [ -n "$SYSTEM_MAP_FILE" ]; then
	echo "#define SNAPAPI_SYSTEM_MAP \"${TARGET_SYSTEM_MAP_PATH}\"" >> "${OUTPUT_FILE}"
	SYMBOLS="printk blk_mq_submit_bio _printk"
	for SYMBOL_NAME in ${SYMBOLS}
	do
		SYMBOL_ADDR=$(grep " ${SYMBOL_NAME}$" "${TARGET_SYSTEM_MAP_PATH}" | awk '{print $1}')
		if [ -z "${SYMBOL_ADDR}" ]
		then
			log_warning "Function \"${SYMBOL_NAME}\" not found"
		else
			MACRO_NAME="$(echo ${SYMBOL_NAME} | awk '{print toupper($0)}')_ADDR"
			echo "#define ${MACRO_NAME} 0x${SYMBOL_ADDR}" >> "${OUTPUT_FILE}"
			log_info "Address of the function \"${SYMBOL_NAME}\" was defined"
		fi
	done
fi

# the end of the config file
echo "#endif" >> "${OUTPUT_FILE}"
