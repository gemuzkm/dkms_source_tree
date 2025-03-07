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

		--arch=*)
			ARCH="${argument#*=}"
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

if [ -z "$ARCH" ]; then
	log_error "--arch parameter is not specified or has empty value"
	print_help
	exit $EINVAL
fi

SNAPAPI_TREE="${DKMS_TREE}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build"

# debug info:
if [ -z ${DO_NOT_BUILD_DEBUG+x} ]; then
	module_dir=/var/lib/dkms/snapapi26/$PACKAGE_VERSION/$KERNEL_VERSION/$ARCH/module

	declare -a modules=("snapapi26" "snumbd26")

	for module in "${modules[@]}"
	do
		strip_file=${module_dir}/${module}.ko
		sym_file=${module_dir}/${module}.sym
		objcopy --only-keep-debug ${strip_file} ${sym_file}
		strip -g ${strip_file}
		objcopy --add-gnu-debuglink=${sym_file} ${strip_file}
	done
fi

make -C "${SNAPAPI_TREE}" clean srctree="${KERNEL_SRC_DIR}" KERNELRELEASE="${KERNEL_VERSION}"
