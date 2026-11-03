package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import gen.etsi.LI_PS_PDU.CPEProvidedLocationAttributes;
import gen.etsi.LI_PS_PDU.PS_PDU;
import org.junit.jupiter.api.Test;

/**
 * The ETSI LI module set generated in its default layout: each ASN.1
 * module's types in a sub-package of {@code --package} named after the
 * module.
 */
class ModulePackagesTest {
    @Test
    void eachModuleHasItsOwnPackage() {
        assertEquals("gen.etsi.LI_PS_PDU", PS_PDU.class.getPackageName());
        assertEquals("gen.etsi.Common_Parameters", gen.etsi.Common_Parameters.GNSSLocation.class.getPackageName());
    }

    @Test
    void aTypeNameOfSeveralModulesKeepsItsNameInEach() {
        Class<?> a = gen.etsi.HI2Operations.IRI_Parameters.class;
        Class<?> b = gen.etsi.EpsHI2Operations.IRI_Parameters.class;
        assertNotSame(a, b);
        assertEquals("IRI_Parameters", a.getSimpleName());
        assertEquals("IRI_Parameters", b.getSimpleName());
    }

    @Test
    void aMemberOfAnotherModulesTypeHasThatModulesClass() throws NoSuchMethodException {
        assertEquals(gen.etsi.Common_Parameters.GNSSLocation.class,
                CPEProvidedLocationAttributes.class.getMethod("gNSSLocation").getReturnType());
    }
}
