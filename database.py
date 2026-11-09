
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "seguridad.db"


def conectar():
    conexion = sqlite3.connect(DB_PATH, timeout=10)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON")
    return conexion


def inicializar_db():
    with conectar() as conexion:
        conexion.execute("""
            CREATE TABLE IF NOT EXISTS incidentes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                descripcion TEXT NOT NULL,
                severidad TEXT NOT NULL,
                estado TEXT NOT NULL DEFAULT 'Abierto',
                ocurrido_en TEXT NOT NULL,
                detectado_en TEXT NOT NULL,
                respondido_en TEXT,
                resuelto_en TEXT,
                creado_en TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conexion.commit()


if __name__ == "__main__":
    inicializar_db()
    print("Base de datos creada correctamente.")
