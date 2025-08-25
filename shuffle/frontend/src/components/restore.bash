for orig in *.orig.*; do
    base="${orig%%.orig.*}"
    cp -f "$orig" "$base"
done
