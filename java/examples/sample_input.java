public class sample_input {
    public static void main(String[] args) {
        int[] seq = fibonacci(8);
        StringBuilder sb = new StringBuilder("FIB [");
        for (int i = 0; i < seq.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(seq[i]);
        }
        sb.append("]");
        System.out.println(sb.toString());
    }

    public static int[] fibonacci(int n) {
        int[] seq = new int[n];
        seq[0] = 0;
        seq[1] = 1;
        for (int i = 2; i < n; i++) seq[i] = seq[i - 1] + seq[i - 2];
        return seq;
    }
}
