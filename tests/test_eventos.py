from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from detectionlab.eventos import (
    ErrorEvento,
    cargar_directorio,
    cargar_eventos,
    existe_campo,
    marca_tiempo,
    obtener_campo,
    valores_planos,
)


@pytest.mark.parametrize(
    ("texto", "esperado"),
    [
        (
            "2026-11-10T08:00:00.000-0300",
            datetime(2026, 11, 10, 8, tzinfo=timezone(timedelta(hours=-3))),
        ),
        ("2026-11-10T11:00:00Z", datetime(2026, 11, 10, 11, tzinfo=UTC)),
        ("2026-11-10T11:00:00", datetime(2026, 11, 10, 11, tzinfo=UTC)),
    ],
)
def test_marca_tiempo_acepta_formatos_de_wazuh(texto: str, esperado: datetime) -> None:
    assert marca_tiempo({"timestamp": texto}) == esperado


def test_marca_tiempo_rechaza_valores_invalidos() -> None:
    with pytest.raises(ErrorEvento):
        marca_tiempo({"timestamp": "ayer"})
    with pytest.raises(ErrorEvento):
        marca_tiempo({})


def test_obtener_campo_y_existe_campo() -> None:
    evento = {"data": {"audit": {"key": None, "exe": "/bin/sh"}}, "lista": [1, 2]}
    assert obtener_campo(evento, "data.audit.exe") == "/bin/sh"
    assert obtener_campo(evento, "data.audit.key") is None
    assert obtener_campo(evento, "data.nada") is None
    assert obtener_campo(evento, "lista.0") is None
    assert existe_campo(evento, "data.audit.key")
    assert not existe_campo(evento, "data.audit.cwd")
    assert sorted(valores_planos(evento)) == ["/bin/sh", "1", "2"]


def test_cargar_eventos_jsonl_y_json(tmp_path: Path) -> None:
    jsonl = tmp_path / "a.jsonl"
    jsonl.write_text('{"timestamp": "x"}\n\n{"timestamp": "y"}\n', encoding="utf-8")
    assert [e["timestamp"] for e in cargar_eventos(jsonl)] == ["x", "y"]
    unico = tmp_path / "b.json"
    unico.write_text('{"timestamp": "z"}', encoding="utf-8")
    assert cargar_eventos(unico) == [{"timestamp": "z"}]
    lista = tmp_path / "sub" / "c.json"
    lista.parent.mkdir()
    lista.write_text('[{"timestamp": "w"}]', encoding="utf-8")
    (tmp_path / "ignorado.txt").write_text("nada", encoding="utf-8")
    assert len(cargar_directorio(tmp_path)) == 4


def test_cargar_eventos_informa_la_linea_invalida(tmp_path: Path) -> None:
    ruta = tmp_path / "malo.jsonl"
    ruta.write_text('{"ok": 1}\n{no es json}\n', encoding="utf-8")
    with pytest.raises(ErrorEvento, match=r"malo\.jsonl:2"):
        cargar_eventos(ruta)
    otro = tmp_path / "malo.json"
    otro.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ErrorEvento, match="no es un objeto"):
        cargar_eventos(otro)
    otro.write_text("{", encoding="utf-8")
    with pytest.raises(ErrorEvento, match="JSON inválido"):
        cargar_eventos(otro)
    otro.write_text('"texto"', encoding="utf-8")
    with pytest.raises(ErrorEvento, match="lista"):
        cargar_eventos(otro)
