package org.openssl.jostle.util.asn1;

public enum PrivateKeyOptions
{
    DEFAULT("default"), SEED_ONLY("seed_only");
    private final String option;

    PrivateKeyOptions(final String value)
    {
        this.option = value;
    }

    public String getValue()
    {
        return option;
    }

    public static PrivateKeyOptions forOption(String option)
    {
        if (option == null)
        {
            return DEFAULT;
        }
        option = option.trim();

        for (PrivateKeyOptions value : values())
        {
            if (value.option.equalsIgnoreCase(option))
            {
                return value;
            }
        }
        throw new IllegalArgumentException("Unknown option: " + option);
    }

}
