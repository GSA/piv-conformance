import java.lang.reflect.Method;

/** Run only the reference runner's pure String comparison helper on synthetic IDs.
 * No reference source is copied, no runner is started and no card is opened.
 */
public final class NistUuidProbe {
    public static void main(String[] args) throws Exception {
        Method method = Class.forName("com.tvec.smart_card.piv.testscript.ScriptItemUtils")
                .getMethod("compareUuid",String.class,String.class);
        String canonical="00112233-4455-4677-8899-aabbccddeeff";
        String expected="00112233445546778899aabbccddeeff";
        String[][] cases={
            {"uuid-link-correct","urn:uuid:"+canonical,"true"},
            {"uuid-link-mismatch","urn:uuid:11223344-5566-4778-8899-aabbccddeeff","false"},
            {"uuid-link-no-hyphens","urn:uuid:"+expected,"true"},
            {"uuid-link-bare",canonical,"true"}
        };
        System.out.println("fixture_id\treference_helper_result");
        for(String[] item:cases) {
            boolean actual=(Boolean)method.invoke(null,item[1],expected);
            if(actual!=Boolean.parseBoolean(item[2])) throw new AssertionError("Reference observation changed: "+item[0]);
            System.out.println(item[0]+"\t"+actual);
        }
    }
}
