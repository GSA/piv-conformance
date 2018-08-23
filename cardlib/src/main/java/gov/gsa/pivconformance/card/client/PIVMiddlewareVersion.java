package gov.gsa.pivconformance.card.client;

/**
 * Class for atoring PIV middleware version information.
 */
public class PIVMiddlewareVersion {

    /**
     *
     * Default constructor that creates an invalid PIVMiddlewareVersion object
     *
     */
    public PIVMiddlewareVersion() {
        version = "NOT SET";
    }

    /**
     *
     * Returns a String with PIV middleware version info
     *
     * @return
     */
    public String getVersion() {
        return version;
    }

    /**
     *
     * Sets the PIV middleware version info
     *
     * @param version String with PIV middleware version info
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     *
     * Returns a String with PIV middleware version info
     *
     * @return
     */
    @Override
    public String toString() {
        return version;
    }

    private String version;

}
