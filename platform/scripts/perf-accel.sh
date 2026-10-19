# Sourced by scripts/run-perf-matrix.sh: resolves ABSD_PERF_ACCEL into the
# QEMU command words, refusing before any build or boot. Sets $accel and
# $qemu. Tested by scripts/test-perf-accel.sh.
#
#   ABSD_PERF_ACCEL   tcg (default) or kvm
#   ABSD_QEMU         the QEMU binary (and harmless options); naming an
#                     accelerator there is refused, so the reported accel=
#                     is the one used
#   ABSD_KVM_DEVICE   the KVM device (default /dev/kvm; tests point it
#                     elsewhere)
accel=${ABSD_PERF_ACCEL:-tcg}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
case " $qemu " in
    *" -accel "* | *" -enable-kvm "* | *" -machine "*accel=* | *" -M "*accel=*)
        echo "run-perf-matrix: ABSD_QEMU names an accelerator; choose it with ABSD_PERF_ACCEL instead" >&2
        exit 2 ;;
esac
case "$accel" in
    kvm)
        # A usable KVM: the device opens read-write and answers
        # KVM_GET_API_VERSION with the stable API version 12.
        kvm_api=$(python3 -I -c '
import fcntl, os, sys
try:
    fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC)
    print(fcntl.ioctl(fd, 0xAE00))
except OSError as error:
    print("error:", error.strerror)
' "${ABSD_KVM_DEVICE:-/dev/kvm}")
        if [ "$kvm_api" != 12 ]; then
            echo "run-perf-matrix: ABSD_PERF_ACCEL=kvm but ${ABSD_KVM_DEVICE:-/dev/kvm} is not a usable KVM (KVM_GET_API_VERSION: $kvm_api)" >&2
            exit 2
        fi
        qemu="$qemu -accel kvm -cpu host" ;;
    tcg) qemu="$qemu -cpu max,vendor=GenuineIntel,+rdrand" ;;
    *) echo "ABSD_PERF_ACCEL must be kvm or tcg" >&2; exit 2 ;;
esac
