package io.github.hairmare.keycloak.extension.openbao.deployment;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

class KeycloakExtensionOpenbaoProcessor {

    private static final String FEATURE = "keycloak-extension-openbao";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }
}
