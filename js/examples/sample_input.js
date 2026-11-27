// Sample script for testing obsor-js obfuscation
function fibonacci(n) {
  const seq = [0, 1];
  for (let i = 0; i < n - 2; i++) {
    seq.push(seq[seq.length - 1] + seq[seq.length - 2]);
  }
  return seq.slice(0, n);
}
console.log('FIB', JSON.stringify(fibonacci(8)));
