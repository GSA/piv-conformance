package gov.gsa.pivconformance.card.client;

public class PIVMiddlewareVersion {
    public PIVMiddlewareVersion() {
        version = "NOT SET";
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public String toString() {
        return version;
    }

    private String version;

}
