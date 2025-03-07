#!/bin/bash

EINVAL=22
THIS_SCRIPT_NAME=$(basename "$0")

function log_error
{
	echo "$THIS_SCRIPT_NAME: error: $@"
}

function print_help
{
	cat <<-ENDHELP
$THIS_SCRIPT_NAME: options...
\toptions:
\t\t--tree=*path to DKMS tree*
\t\t--package=*name of package to be built*
\t\t--version=*version of package to be built*
\t\t--kernel_src_dir=*path to the kernel sources*
\t\t--kver=*kernel version (uname -r)*
ENDHELP
}

for argument in "$@"; do
	case "$argument" in
		--tree=*)
			DKMS_TREE="${argument#*=}"
			;;

		--package=*)
			PACKAGE_NAME="${argument#*=}"
			;;

		--version=*)
			PACKAGE_VERSION="${argument#*=}"
			;;

		--kernel_src_dir=*)
			KERNEL_SRC_DIR="${argument#*=}"
			;;

		--kver=*)
			KERNEL_VERSION="${argument#*=}"
			;;
	esac
done

if [ -z "$DKMS_TREE" ]; then
	log_error "--tree parameter is not specified or has empty value"
	print_help
	exit $EINVAL
fi

if [ -z "$PACKAGE_NAME" ]; then
	log_error "--package parameter is not specified or has empty value"
	print_help
	exit $EINVAL
fi

if [ -z "$PACKAGE_VERSION" ]; then
	log_error "--version parameter is not specified or has empty value"
	print_help
	exit $EINVAL
fi

if [ -z "$KERNEL_SRC_DIR" ]; then
	log_error "--kernel_src_dir parameter is not specified or has empty value"
	print_help
	exit $EINVAL
fi

if [ -z "$KERNEL_VERSION" ]; then
	log_error "--kver parameter is not specified or has empty value"
	print_help
	exit $EINVAL
fi

SNAPAPI_TREE="${DKMS_TREE}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build"

make -C "${SNAPAPI_TREE}" snapapi_system_map srctree="${KERNEL_SRC_DIR}" KERNELRELEASE="${KERNEL_VERSION}"
