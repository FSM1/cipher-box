import { useState, useEffect, useRef, useCallback } from 'react';
import type { FileEntry } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFilePreview } from '../../hooks/useFilePreview';
import '../../styles/audio-player-dialog.css';

type AudioPlayerDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FileEntry | null;
};

/** Map common audio extensions to MIME types. */
const AUDIO_MIME: Record<string, string> = {
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.ogg': 'audio/ogg',
  '.m4a': 'audio/mp4',
  '.flac': 'audio/flac',
};

function getAudioMime(filename: string): string {
  const lower = filename.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return 'audio/mpeg';
  return AUDIO_MIME[lower.slice(lastDot)] ?? 'audio/mpeg';
}

function formatTime(seconds: number): string {
  if (!isFinite(seconds) || seconds < 0) return '00:00';
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

/**
 * Modal dialog for playing audio files with custom controls.
 *
 * Uses Web Audio API AnalyserNode for frequency spectrum visualization.
 * No native browser audio controls -- fully custom transport UI.
 */
export function AudioPlayerDialog({ open, onClose, item }: AudioPlayerDialogProps) {
  const mimeType = item ? getAudioMime(item.name) : 'audio/mpeg';
  const { loading, error, objectUrl, handleDownload } = useFilePreview({
    open,
    item,
    mimeType,
  });

  // Audio state
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(0.7);
  const [vizEnabled, setVizEnabled] = useState(true);

  // Refs
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const sourceRef = useRef<MediaElementAudioSourceNode | null>(null);
  const animFrameRef = useRef<number>(0);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const progressRef = useRef<HTMLDivElement | null>(null);

  // Create Audio element and connect Web Audio API when objectUrl is ready
  useEffect(() => {
    if (!objectUrl) {
      // Cleanup on close
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
        animFrameRef.current = 0;
      }
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.src = '';
        audioRef.current = null;
      }
      if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
        audioContextRef.current.close().catch(() => {});
      }
      audioContextRef.current = null;
      analyserRef.current = null;
      sourceRef.current = null;
      setIsPlaying(false);
      setCurrentTime(0);
      setDuration(0);
      return;
    }

    const audio = new Audio(objectUrl);
    audio.volume = volume;
    audio.crossOrigin = 'anonymous';
    audioRef.current = audio;

    const handleTimeUpdate = () => setCurrentTime(audio.currentTime);
    const handleLoadedMetadata = () => setDuration(audio.duration);
    const handleEnded = () => setIsPlaying(false);

    audio.addEventListener('timeupdate', handleTimeUpdate);
    audio.addEventListener('loadedmetadata', handleLoadedMetadata);
    audio.addEventListener('ended', handleEnded);

    // Set up Web Audio API
    try {
      const ctx = new AudioContext();
      audioContextRef.current = ctx;

      const analyser = ctx.createAnalyser();
      analyser.fftSize = 128;
      analyser.smoothingTimeConstant = 0.8;
      analyserRef.current = analyser;

      const source = ctx.createMediaElementSource(audio);
      sourceRef.current = source;
      source.connect(analyser);
      analyser.connect(ctx.destination);
    } catch (err) {
      console.warn('Web Audio API setup failed:', err);
    }

    return () => {
      audio.removeEventListener('timeupdate', handleTimeUpdate);
      audio.removeEventListener('loadedmetadata', handleLoadedMetadata);
      audio.removeEventListener('ended', handleEnded);

      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
        animFrameRef.current = 0;
      }
      audio.pause();
      audio.src = '';

      if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
        audioContextRef.current.close().catch(() => {});
      }
      audioContextRef.current = null;
      analyserRef.current = null;
      sourceRef.current = null;
    };
  }, [objectUrl]);

  // Sync volume to audio element
  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.volume = volume;
    }
  }, [volume]);

  // Frequency visualization animation loop
  useEffect(() => {
    if (!vizEnabled || !isPlaying || !analyserRef.current || !canvasRef.current) {
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
        animFrameRef.current = 0;
      }
      return;
    }

    const analyser = analyserRef.current;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const bufferLength = analyser.frequencyBinCount; // 64
    const dataArray = new Uint8Array(bufferLength);
    const barCount = 48;

    const draw = () => {
      animFrameRef.current = requestAnimationFrame(draw);
      analyser.getByteFrequencyData(dataArray);

      const w = canvas.width;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);

      const barWidth = 8;
      const barGap = 4;
      const totalWidth = barCount * (barWidth + barGap) - barGap;
      const startX = (w - totalWidth) / 2;

      for (let i = 0; i < barCount; i++) {
        const dataIndex = Math.floor((i / barCount) * bufferLength);
        const value = dataArray[dataIndex] / 255;
        const barHeight = Math.max(2, value * h * 0.85);

        const x = startX + i * (barWidth + barGap);
        const y = h - barHeight;

        // Gradient from green primary to darker green at bottom
        const gradient = ctx.createLinearGradient(x, y, x, h);
        gradient.addColorStop(0, '#00D084');
        gradient.addColorStop(1, '#006644');
        ctx.fillStyle = gradient;
        ctx.fillRect(x, y, barWidth, barHeight);
      }
    };

    draw();

    return () => {
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
        animFrameRef.current = 0;
      }
    };
  }, [vizEnabled, isPlaying]);

  // Resize canvas to fit container
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        canvas.width = width * window.devicePixelRatio;
        canvas.height = height * window.devicePixelRatio;
      }
    });

    resizeObserver.observe(canvas.parentElement!);
    return () => resizeObserver.disconnect();
  }, [objectUrl]);

  // Transport controls
  const handlePlayPause = useCallback(async () => {
    const audio = audioRef.current;
    if (!audio) return;

    // Resume AudioContext if suspended (browser autoplay policy)
    if (audioContextRef.current?.state === 'suspended') {
      await audioContextRef.current.resume();
    }

    if (isPlaying) {
      audio.pause();
      setIsPlaying(false);
    } else {
      try {
        await audio.play();
        setIsPlaying(true);
      } catch {
        // Browser blocked playback (autoplay policy / interruption)
      }
    }
  }, [isPlaying]);

  const handleSkipStart = useCallback(() => {
    if (audioRef.current) {
      audioRef.current.currentTime = 0;
    }
  }, []);

  const handleSkipForward = useCallback(() => {
    if (audioRef.current) {
      audioRef.current.currentTime = Math.min(
        audioRef.current.currentTime + 10,
        audioRef.current.duration || 0
      );
    }
  }, []);

  const handleVolumeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setVolume(parseFloat(e.target.value));
  }, []);

  const handleVizToggle = useCallback(() => {
    setVizEnabled((v) => !v);
  }, []);

  // Seek via progress bar click
  const handleProgressClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const audio = audioRef.current;
      if (!audio || !progressRef.current || !duration) return;

      const rect = progressRef.current.getBoundingClientRect();
      const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      audio.currentTime = ratio * duration;
    },
    [duration]
  );

  const handleClose = useCallback(() => {
    // Stop playback before closing
    if (audioRef.current) {
      audioRef.current.pause();
    }
    setIsPlaying(false);
    onClose();
  }, [onClose]);

  if (!item) return null;

  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <Modal open={open} onClose={handleClose} className="audio-player-modal">
      {loading ? (
        <div className="audio-preview-loading">decrypting...</div>
      ) : error ? (
        <div className="audio-preview-error">
          {'> '}
          {error}
        </div>
      ) : (
        <>
          {/* Toolbar */}
          <div className="audio-toolbar">
            <div className="audio-toolbar-left">
              <span className="audio-tag">AUD</span>
              <span className="audio-filename">{item.name}</span>
            </div>
            <div className="audio-toolbar-right">
              <button
                type="button"
                className="audio-btn"
                onClick={handleDownload}
                aria-label="Download file"
              >
                [download]
              </button>
            </div>
          </div>

          {/* Visualization area */}
          <div className="audio-viz-area">
            {vizEnabled ? (
              <canvas ref={canvasRef} />
            ) : (
              <span className="audio-viz-placeholder">{'// visualization disabled'}</span>
            )}
          </div>

          {/* Progress bar */}
          <div className="audio-progress-wrapper">
            <div
              className="audio-progress-track"
              ref={progressRef}
              onClick={handleProgressClick}
              onKeyDown={(e) => {
                const audio = audioRef.current;
                if (!audio || !duration) return;
                if (e.key === 'ArrowRight')
                  audio.currentTime = Math.min(duration, audio.currentTime + 5);
                else if (e.key === 'ArrowLeft')
                  audio.currentTime = Math.max(0, audio.currentTime - 5);
              }}
              role="slider"
              aria-label="Audio progress"
              aria-valuemin={0}
              aria-valuemax={Math.floor(duration)}
              aria-valuenow={Math.floor(currentTime)}
              tabIndex={0}
            >
              <div className="audio-progress-fill" style={{ width: `${progressPercent}%` }} />
            </div>
            <div className="audio-timestamps">
              <span>{formatTime(currentTime)}</span>
              <span>{formatTime(duration)}</span>
            </div>
          </div>

          {/* Transport controls */}
          <div className="audio-controls">
            <div className="audio-controls-group">
              <button
                type="button"
                className="audio-btn"
                onClick={handleSkipStart}
                aria-label="Skip to start"
              >
                |&lt;&lt;
              </button>
              <button
                type="button"
                className="audio-btn"
                onClick={handlePlayPause}
                aria-label={isPlaying ? 'Pause' : 'Play'}
              >
                {isPlaying ? '[PAUSE]' : '[PLAY]'}
              </button>
              <button
                type="button"
                className="audio-btn"
                onClick={handleSkipForward}
                aria-label="Skip forward 10 seconds"
              >
                &gt;&gt;|
              </button>
            </div>

            <div className="audio-volume-wrapper">
              <span className="audio-volume-label">vol:</span>
              <input
                type="range"
                className="audio-volume-slider"
                min="0"
                max="1"
                step="0.01"
                value={volume}
                onChange={handleVolumeChange}
                aria-label="Volume"
              />
            </div>

            <button
              type="button"
              className="audio-btn"
              onClick={handleVizToggle}
              aria-label={vizEnabled ? 'Disable visualization' : 'Enable visualization'}
            >
              [viz: {vizEnabled ? 'on' : 'off'}]
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
