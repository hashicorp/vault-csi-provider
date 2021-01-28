wait_for_success() {
  echo $1
  for i in {0..60}; do
      if eval "$1"; then
          return
      fi
      sleep 1
  done
  # Fail the test.
  [ 1 -eq 2 ]
}