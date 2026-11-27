public class sample_with_private {
    private static String secretGreeting = "classified greeting text";

    private static String format(String s) {
        return "[" + s + "]";
    }

    public static void run() {
        System.out.println(format(secretGreeting));
    }

    public static void main(String[] args) {
        run();
    }
}
