"""
Kubernetes: contencion sobre el API server con un ServiceAccount propio.

RBAC minimo del ServiceAccount de ResponseLab (en docs/CONECTORES.md):
patch nodes; get/patch pods; create/delete networkpolicies; get/delete/create
rolebindings y clusterrolebindings; get/patch deployments/scale y
statefulsets/scale.

Aislar un pod: la NetworkPolicy no selecciona las etiquetas del workload (eso
aislaria todas sus replicas), sino una etiqueta propia que se pone antes solo
en el pod afectado. El radio es ese pod, no el servicio.
"""
from __future__ import annotations

import re

from .base import Conector, NoSoportada, Resultado

RE_NOMBRE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")


def _campo(objetivo, contexto, ruta):
    from ..nucleo import leer
    return objetivo.get(ruta) or leer(contexto.get("alerta") or {}, ruta)


def _nombre(valor, que) -> str:
    v = str(valor or "")
    if not RE_NOMBRE.match(v):
        raise NoSoportada(f"{que} no valido para Kubernetes: {v!r}")
    return v


class Kubernetes(Conector):
    nombre = "kubernetes"
    requiere_cfg = ("url",)
    requiere_secretos = ("token",)
    acciones = {
        "k8s.acordonar_nodo": "acordonar",
        "k8s.desacordonar_nodo": "desacordonar",
        "k8s.aislar_pod": "aislar_pod",
        "k8s.liberar_pod": "liberar_pod",
        "k8s.retirar_rolebinding": "retirar_binding",
        "k8s.restaurar_rolebinding": "restaurar_binding",
        "k8s.escalar_cero": "escalar_cero",
        "k8s.restaurar_replicas": "restaurar_replicas",
    }

    def _u(self, ruta):
        return self.cfg["url"].rstrip("/") + ruta

    def _cab(self, tipo="application/json"):
        return {"Authorization": f"Bearer {self.secreto('token')}", "Content-Type": tipo}

    async def _parche(self, http, ruta, cuerpo):
        import json
        return await http.peticion("PATCH", self._u(ruta), cabeceras=self._cab("application/merge-patch+json"),
                                   contenido=json.dumps(cuerpo))

    async def acordonar(self, http, objetivo, parametros, contexto):
        nodo = _nombre(_campo(objetivo, contexto, "k8s.nodo"), "nodo")
        await self._parche(http, f"/api/v1/nodes/{nodo}", {"spec": {"unschedulable": True}})
        return Resultado("ok", f"nodo {nodo} acordonado", {"nodo": nodo})

    async def desacordonar(self, http, objetivo, parametros, contexto):
        nodo = (contexto.get("datos_deshacer") or {}).get("nodo") or _nombre(_campo(objetivo, contexto, "k8s.nodo"), "nodo")
        await self._parche(http, f"/api/v1/nodes/{nodo}", {"spec": {"unschedulable": False}})
        return Resultado("ok", f"nodo {nodo} desacordonado")

    async def aislar_pod(self, http, objetivo, parametros, contexto):
        ns = _nombre(_campo(objetivo, contexto, "k8s.namespace"), "namespace")
        pod = _nombre(_campo(objetivo, contexto, "k8s.pod"), "pod")
        marca = f"rl-{contexto.get('ejecucion_id', 'x')[-12:]}".lower()
        await self._parche(http, f"/api/v1/namespaces/{ns}/pods/{pod}",
                           {"metadata": {"labels": {"responselab-aislado": marca}}})
        politica = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": f"responselab-aislar-{marca}", "namespace": ns,
                         "labels": {"app.kubernetes.io/managed-by": "responselab"}},
            "spec": {"podSelector": {"matchLabels": {"responselab-aislado": marca}},
                     "policyTypes": ["Egress", "Ingress"], "egress": [], "ingress": []},
        }
        await http.peticion("POST", self._u(f"/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies"),
                            cabeceras=self._cab(), json_=politica)
        return Resultado("ok", f"pod {ns}/{pod} aislado (entrada y salida)", {"ns": ns, "pod": pod, "marca": marca})

    async def liberar_pod(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        if not d.get("marca"):
            raise NoSoportada("no se guardo la marca del aislamiento")
        await http.peticion("DELETE", self._u(f"/apis/networking.k8s.io/v1/namespaces/{d['ns']}/networkpolicies/"
                                              f"responselab-aislar-{d['marca']}"), cabeceras=self._cab(),
                            esperado=(200, 202, 404))
        await self._parche(http, f"/api/v1/namespaces/{d['ns']}/pods/{d['pod']}",
                           {"metadata": {"labels": {"responselab-aislado": None}}})
        return Resultado("ok", f"pod {d['ns']}/{d['pod']} liberado")

    def _ruta_binding(self, ref: str) -> tuple[str, dict]:
        # ref: "rolebindings/<ns>/<nombre>" o "clusterrolebindings/<nombre>"
        partes = str(ref).strip("/").split("/")
        if partes[0] == "clusterrolebindings" and len(partes) == 2:
            return f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{_nombre(partes[1], 'binding')}", {}
        if partes[0] == "rolebindings" and len(partes) == 3:
            ns, nombre = _nombre(partes[1], "namespace"), _nombre(partes[2], "binding")
            return f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{nombre}", {"ns": ns}
        raise NoSoportada(f"referencia de binding no reconocida: {ref!r}")

    async def retirar_binding(self, http, objetivo, parametros, contexto):
        ref = _campo(objetivo, contexto, "k8s.rolebinding")
        ruta, _ = self._ruta_binding(ref)
        r = await http.peticion("GET", self._u(ruta), cabeceras=self._cab(),
                                simulada={"kind": "RoleBinding", "metadata": {"name": "simulado"}})
        manifiesto = r.json()
        for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields", "generation", "selfLink"):
            (manifiesto.get("metadata") or {}).pop(k, None)
        await http.peticion("DELETE", self._u(ruta), cabeceras=self._cab())
        return Resultado("ok", f"binding {ref} retirado (manifiesto guardado)", {"ref": ref, "manifiesto": manifiesto})

    async def restaurar_binding(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        if not d.get("manifiesto"):
            raise NoSoportada("no hay manifiesto guardado")
        ruta, _ = self._ruta_binding(d["ref"])
        coleccion = ruta.rsplit("/", 1)[0]
        await http.peticion("POST", self._u(coleccion), cabeceras=self._cab(), json_=d["manifiesto"])
        return Resultado("ok", f"binding {d['ref']} recreado")

    def _ruta_escala(self, objetivo, contexto) -> str:
        ns = _nombre(_campo(objetivo, contexto, "k8s.namespace"), "namespace")
        workload = str(_campo(objetivo, contexto, "k8s.workload") or "")
        tipo, _, nombre = workload.partition("/")
        if tipo not in ("deployment", "statefulset"):
            raise NoSoportada("k8s.workload debe ser deployment/<nombre> o statefulset/<nombre>")
        return f"/apis/apps/v1/namespaces/{ns}/{tipo}s/{_nombre(nombre, 'workload')}/scale"

    async def escalar_cero(self, http, objetivo, parametros, contexto):
        ruta = self._ruta_escala(objetivo, contexto)
        r = await http.peticion("GET", self._u(ruta), cabeceras=self._cab(), simulada={"spec": {"replicas": 3}})
        replicas = int((r.json().get("spec") or {}).get("replicas", 1))
        await self._parche(http, ruta, {"spec": {"replicas": 0}})
        return Resultado("ok", f"workload a 0 replicas (tenia {replicas})", {"ruta": ruta, "replicas": replicas})

    async def restaurar_replicas(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        if "replicas" not in d:
            raise NoSoportada("no se guardo el numero de replicas")
        await self._parche(http, d["ruta"], {"spec": {"replicas": int(d["replicas"])}})
        return Resultado("ok", f"workload devuelto a {d['replicas']} replicas")
