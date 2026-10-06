"""GPU thermal governor tests."""

from types import SimpleNamespace
from unittest.mock import patch

from app.services.gpu_thermal import (
    GpuStats,
    ThermalSettings,
    adaptive_embed_batch_size,
    get_gpu_stats,
    is_gpu_hot,
    reset_embed_duty_counter,
    thermal_guard_after_batch,
    wait_for_gpu_cooldown,
    _load_settings,
)


def _classic_settings() -> ThermalSettings:
    return ThermalSettings(
        enabled=True,
        pause_c=74,
        resume_c=62,
        throttle_c=68,
        poll_sec=2.0,
        hot_sleep_sec=6.0,
        embed_rest_sec=1.0,
        duty_batches=3,
        duty_rest_sec=5.0,
        adaptive_batch=True,
        power_limit_w=70,
        start_max_c=58,
        cool_boost_c=50,
        cool_batch_multiplier=1.25,
        fallback_duty=True,
        rise_delta_c=5,
        rise_window_sec=15.0,
        abort_c=82,
    )


def test_honor_env_keeps_configured_pause_and_abort(monkeypatch):
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: SimpleNamespace(
            gpu_thermal_enabled=True,
            gpu_thermal_pause_c=92,
            gpu_thermal_resume_c=84,
            gpu_thermal_throttle_c=87,
            gpu_thermal_poll_sec=2.0,
            gpu_thermal_hot_batch_sleep_sec=4.0,
            gpu_thermal_embed_rest_sec=0.35,
            gpu_thermal_duty_cycle_batches=6,
            gpu_thermal_duty_cycle_rest_sec=2.0,
            gpu_thermal_adaptive_batch=True,
            gpu_thermal_power_limit_w=70,
            gpu_thermal_start_max_c=90,
            gpu_thermal_cool_boost_c=58,
            gpu_thermal_cool_batch_multiplier=1.0,
            gpu_thermal_fallback_duty=True,
            gpu_thermal_rise_delta_c=8,
            gpu_thermal_rise_window_sec=10.0,
            gpu_thermal_abort_c=94,
            gpu_thermal_honor_env=True,
        ),
    )
    settings = _load_settings(gpu_name="NVIDIA GeForce RTX 5070 Ti Laptop GPU")
    assert settings.pause_c == 92
    assert settings.abort_c == 94
    assert settings.throttle_c == 87
    with patch("app.services.gpu_thermal._read_via_pynvml") as mock:
        mock.return_value = GpuStats(
            available=True,
            temperature_c=52,
            name="NVIDIA GeForce RTX 5070 Ti Laptop GPU",
            source="test",
        )
        stats = get_gpu_stats()
        assert stats.hot is False
        assert stats.throttling is False


def test_hot_detection():
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal._read_via_pynvml") as mock:
            mock.return_value = GpuStats(available=True, temperature_c=88, source="test")
            stats = get_gpu_stats()
            assert stats.hot is True
            assert is_gpu_hot() is True


def test_throttling_detection():
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal._read_via_pynvml") as mock:
            mock.return_value = GpuStats(available=True, temperature_c=70, source="test")
            stats = get_gpu_stats()
            assert stats.throttling is True
            assert stats.hot is False


def test_cool_gpu_no_wait():
    with patch("app.services.gpu_thermal._read_via_pynvml") as mock:
        mock.return_value = GpuStats(available=True, temperature_c=65, source="test")
        assert wait_for_gpu_cooldown(reason="test") == 0.0


def test_cooldown_resumes_once_below_pause():
    temps = [75, 75, 73]

    def _stats():
        t = temps.pop(0) if temps else 73
        return GpuStats(available=True, temperature_c=t, source="test")

    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats", side_effect=_stats):
            with patch("app.services.gpu_thermal.time.sleep", return_value=None):
                waited = wait_for_gpu_cooldown(reason="test", max_wait_sec=30)
    assert waited > 0


def test_cooldown_times_out_instead_of_waiting_for_62c():
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch(
            "app.services.gpu_thermal.get_gpu_stats",
            return_value=GpuStats(available=True, temperature_c=76, source="test"),
        ):
            with patch("app.services.gpu_thermal.time.sleep", return_value=None):
                with patch("app.services.gpu_thermal.time.time", side_effect=[0, 0, 100, 100, 100]):
                    waited = wait_for_gpu_cooldown(reason="test", max_wait_sec=90)
    assert waited >= 0


def test_unavailable_gpu():
    with patch("app.services.gpu_thermal._read_via_pynvml", return_value=None):
        with patch("app.services.gpu_thermal._read_via_nvidia_smi", return_value=None):
            stats = get_gpu_stats()
            assert stats.available is False


def test_adaptive_batch_shrinks_when_hot():
    reset_embed_duty_counter()
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock:
            mock.return_value = GpuStats(available=True, temperature_c=79, source="test")
            assert adaptive_embed_batch_size(12, gpu=True) == 3


def test_adaptive_batch_halves_when_warm():
    reset_embed_duty_counter()
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock:
            mock.return_value = GpuStats(available=True, temperature_c=73, source="test")
            assert adaptive_embed_batch_size(12, gpu=True) == 6


def test_adaptive_batch_full_when_cool():
    reset_embed_duty_counter()
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock:
            mock.return_value = GpuStats(available=True, temperature_c=62, source="test")
            assert adaptive_embed_batch_size(12, gpu=True) == 12


def test_adaptive_batch_boosts_when_cool():
    reset_embed_duty_counter()
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock:
            mock.return_value = GpuStats(available=True, temperature_c=48, source="test")
            assert adaptive_embed_batch_size(12, gpu=True) == 15


def test_adaptive_batch_conservative_without_sensor():
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock:
            mock.return_value = GpuStats(available=False)
            assert adaptive_embed_batch_size(12, gpu=True) == 9


def test_ocr_cool_path_skips_embed_duty_sleep():
    reset_embed_duty_counter()
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock_stats:
            mock_stats.return_value = GpuStats(available=True, temperature_c=55, source="test")
            with patch("app.services.gpu_thermal.time.sleep") as mock_sleep:
                thermal_guard_after_batch(reason="glm_ocr")
                mock_sleep.assert_not_called()


def test_duty_cycle_rest_every_n_batches():
    reset_embed_duty_counter()
    with patch("app.services.gpu_thermal._load_settings", return_value=_classic_settings()):
        with patch("app.services.gpu_thermal.get_gpu_stats") as mock_stats:
            mock_stats.return_value = GpuStats(available=True, temperature_c=74, source="test")
            with patch("app.services.gpu_thermal.time.sleep") as mock_sleep:
                for _ in range(3):
                    thermal_guard_after_batch(reason="test")
                assert mock_sleep.call_count == 3
                assert mock_sleep.call_args_list[-1].args[0] >= 2.0
