public class App {
    // Loaded via a custom ClassLoader (see Obsor.Pro's native-logic tier), so
    // this must use System.load() with the absolute path the launcher hands
    // off via the "obsor.native.lib.path" system property -- JNI resolves a
    // native library against the ClassLoader that loaded it, which must
    // match the ClassLoader of the class declaring the native method (this
    // class), not the launcher's own ClassLoader. Plain System.loadLibrary()
    // would fail with "no obsor_native in java.library.path" since nothing
    // adds this jar's own directory to that path automatically.
    static { System.load(System.getProperty("obsor.native.lib.path")); }

    private static native long secretTransform(long x);

    public static void main(String[] args) {
        System.out.println("computed token: " + secretTransform(7));
    }
}
