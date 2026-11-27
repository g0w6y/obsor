// obsorNative is injected as a global by the native-logic loader.
const token = obsorNative.secret_transform(7);
console.log('computed token:', token);
