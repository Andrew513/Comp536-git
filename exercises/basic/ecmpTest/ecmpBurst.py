for i in $(seq 1 200); do
  ../send.py 10.0.2.2 "ecmp test $i"
done
