from __future__ import annotations

# from dataclasses import dataclass
import base64

import kubernetes
import urllib3
from certificate.certs import CertificateInfo
from certificate.data import Parameters
from certificate.data import Secrets
from kubernetes import config
from kubernetes.client.rest import ApiException
from retry import retry
from rich.console import Console

# from dataclasses import dataclass

console = Console()
config.load_kube_config()


class KubernetesSecrets:
    kubernetes_certificates: list[Secrets]
    api_client: kubernetes.client.ApiClient
    v1: kubernetes.client.CoreV1Api
    """
    Class to manage Kubernetes secrets.
    """

    def __init__(self, parameters: Parameters) -> None:
        self.parameters = parameters
        self.kubernetes_certificates = []

        self.api_client = kubernetes.client.ApiClient()
        self.v1 = kubernetes.client.CoreV1Api(self.api_client)

    def close(self):
        if self.api_client:
            self.api_client.close()

    @retry((ApiException, urllib3.exceptions.MaxRetryError), tries=3, delay=2)
    def find_secrets(self) -> Secrets:
        """
        List all the Kubernetes secrets.
        """

        try:
            secrets = self.v1.list_secret_for_all_namespaces(
                field_selector="type=kubernetes.io/tls"
            ).items

            for secret in secrets:
                # Decode the certificate
                data = base64.b64decode(secret.data["tls.crt"])

                # Load the certificate
                kubernetes_certificate = CertificateInfo.load_certificate_string(
                    data, self.parameters
                )

                # Compare the domains
                if set(self.parameters.cert.domains).intersection(
                    kubernetes_certificate.domains
                ):
                    self.kubernetes_certificates.append(
                        Secrets(
                            name=secret.metadata.name,
                            namespace=secret.metadata.namespace,
                            certificate=kubernetes_certificate,
                        )
                    )
                    if self.parameters.verbose:
                        console.print(
                            f"Secret: {secret.metadata.name} in namespace: {secret.metadata.namespace}",  # noqa
                            style="bold yellow",
                        )

        except ApiException as error:
            console.print(f"Error listing secrets: {error}", style="bold red")

        except urllib3.exceptions.MaxRetryError as error:
            console.print(f"MaxRetryError: {error}", style="bold red")

        finally:
            self.close()

        return self

    def get_secrets(self):
        return self.kubernetes_certificates

    @retry((ApiException, urllib3.exceptions.MaxRetryError), tries=3, delay=2)
    def patch_secret(self) -> None:
        """ """

        secret_data = {
            "data": {
                "tls.crt": CertificateInfo.get_base64(self.parameters.cert_path),
                "tls.key": CertificateInfo.get_base64(self.parameters.key_path),
            }
        }

        try:
            for secret in self.kubernetes_certificates:
                try:
                    self.v1.patch_namespaced_secret(
                        name=secret.name,
                        namespace=secret.namespace,
                        body=secret_data,
                        pretty="true",
                    )

                    if self.parameters.verbose:
                        console.print(
                            f"Secret {secret.name} in namespace {secret.namespace} patched successfully.",  # noqa
                            style="bold yellow",
                        )

                except ApiException as error:
                    console.print(
                        f"Error patching secret {secret.name} in namespace {secret.namespace}: {error}",  # noqa
                        style="bold red",
                    )

        finally:
            self.close()

