
import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, abort
)

from database import conectar, inicializar_db

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY"
) or secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# Protección CSRF para formularios
@app.before_request
def proteger_formularios():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        token_sesion = session.get("csrf_token", "")

        if not token_sesion or not secrets.compare_digest(
            token, token_sesion
        ):
            abort(400, description="Token de seguridad inválido.")

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


# Encabezados básicos de seguridad
@app.after_request
def encabezados_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def obtener_tiempo_promedio(registros, campo_inicio, campo_fin):
    tiempos = []

    for registro in registros:
        inicio = datetime.fromisoformat(registro[campo_inicio])
        fin = datetime.fromisoformat(registro[campo_fin])

        minutos = (fin - inicio).total_seconds() / 60
        tiempos.append(minutos)

    if not tiempos:
        return "Sin datos"

    promedio = sum(tiempos) / len(tiempos)

    if promedio < 60:
        return f"{promedio:.1f} min"

    return f"{promedio / 60:.1f} h"


@app.route("/")
def inicio():
    with conectar() as conexion:
        conexion.row_factory = sqlite3.Row

        incidentes = conexion.execute(
            "SELECT * FROM incidentes ORDER BY id DESC"
        ).fetchall()

        total = conexion.execute(
            "SELECT COUNT(*) FROM incidentes"
        ).fetchone()[0]

        abiertos = conexion.execute(
            "SELECT COUNT(*) FROM incidentes WHERE estado = ?",
            ("Abierto",)
        ).fetchone()[0]

        registros_mttd = conexion.execute("""
            SELECT ocurrido_en, detectado_en
            FROM incidentes
            WHERE detectado_en IS NOT NULL
        """).fetchall()

        registros_mttr = conexion.execute("""
            SELECT detectado_en, resuelto_en
            FROM incidentes
            WHERE resuelto_en IS NOT NULL
        """).fetchall()

    mttd = obtener_tiempo_promedio(
        registros_mttd, "ocurrido_en", "detectado_en"
    )

    mttr = obtener_tiempo_promedio(
        registros_mttr, "detectado_en", "resuelto_en"
    )

    return render_template(
        "index.html",
        incidentes=incidentes,
        total=total,
        abiertos=abiertos,
        mttd=mttd,
        mttr=mttr,
        csrf_token=session["csrf_token"]
    )


@app.route("/registrar", methods=["POST"])
def registrar():
    titulo = request.form.get("titulo", "").strip()
    descripcion = request.form.get("descripcion", "").strip()
    severidad = request.form.get("severidad", "").strip()
    ocurrido = request.form.get("ocurrido_en", "").strip()
    detectado = request.form.get("detectado_en", "").strip()

    severidades_validas = ["Baja", "Media", "Alta", "Crítica"]

    if not titulo or not descripcion:
        abort(400, description="Completa el título y la descripción.")

    if len(titulo) > 120 or len(descripcion) > 2000:
        abort(400, description="Los datos superan la longitud permitida.")

    if severidad not in severidades_validas:
        abort(400, description="Severidad no válida.")

    try:
        fecha_ocurrencia = datetime.fromisoformat(ocurrido)
        fecha_deteccion = datetime.fromisoformat(detectado)
    except ValueError:
        abort(400, description="Formato de fecha no válido.")

    ahora = datetime.now()

    if fecha_deteccion < fecha_ocurrencia:
        abort(400, description="La detección no puede ser anterior al incidente.")

    if fecha_ocurrencia > ahora or fecha_deteccion > ahora:
        abort(400, description="Las fechas no pueden estar en el futuro.")

    with conectar() as conexion:
        conexion.execute("""
            INSERT INTO incidentes (
                titulo, descripcion, severidad,
                estado, ocurrido_en, detectado_en
            )
            VALUES (?, ?, ?, 'Abierto', ?, ?)
        """, (
            titulo,
            descripcion,
            severidad,
            fecha_ocurrencia.isoformat(),
            fecha_deteccion.isoformat()
        ))

    return redirect(url_for("inicio"))


@app.route("/resolver/<int:incidente_id>", methods=["POST"])
def resolver(incidente_id):
    with conectar() as conexion:
        incidente = conexion.execute(
            "SELECT * FROM incidentes WHERE id = ?",
            (incidente_id,)
        ).fetchone()

        if incidente is None:
            abort(404)

        if incidente["estado"] != "Resuelto":
            ahora = datetime.now().isoformat(timespec="seconds")

            conexion.execute("""
                UPDATE incidentes
                SET estado = 'Resuelto',
                    respondido_en = ?,
                    resuelto_en = ?
                WHERE id = ?
            """, (ahora, ahora, incidente_id))

    return redirect(url_for("inicio"))


if __name__ == "__main__":
    inicializar_db()
    app.run(debug=True)
