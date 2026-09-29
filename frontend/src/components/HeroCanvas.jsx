import { useEffect, useRef } from 'react';
import { useReducedMotion } from 'motion/react';

// A quiet particle-network backdrop behind the hero shield: a handful of
// points drifting slowly, joined by lines when they pass close to each
// other - a "security network" motif that stays out of the way of the
// text and buttons in front of it. Colors are read from the page's own
// CSS variables at mount and on theme toggle, so it always matches the
// current theme rather than carrying its own palette.
export default function HeroCanvas() {
  const mountRef = useRef(null);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    if (reducedMotion) return undefined;
    const mount = mountRef.current;
    if (!mount || typeof window === 'undefined') return undefined;

    let frame = 0;
    let disposed = false;
    let cleanup = () => {};

    import('three').then((THREE) => {
      if (disposed || !mount) return;

      const readColor = (name, fallback) => {
        const value = getComputedStyle(document.documentElement)
          .getPropertyValue(name)
          .trim();
        return new THREE.Color(value || fallback);
      };

      const width = mount.clientWidth || 1;
      const height = mount.clientHeight || 1;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
      camera.position.z = 9;

      const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      renderer.setPixelRatio(dpr);
      renderer.setSize(width, height);
      renderer.setClearColor(0x000000, 0);
      mount.appendChild(renderer.domElement);

      const accent = readColor('--accent', '#12654c');
      const soft = readColor('--soft', '#e9f3ed');

      const COUNT = 42;
      const positions = new Float32Array(COUNT * 3);
      const velocities = [];
      for (let i = 0; i < COUNT; i += 1) {
        positions[i * 3] = (Math.random() - 0.5) * 10;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 6;
        positions[i * 3 + 2] = (Math.random() - 0.5) * 4;
        velocities.push({
          x: (Math.random() - 0.5) * 0.004,
          y: (Math.random() - 0.5) * 0.004,
          z: (Math.random() - 0.5) * 0.002,
        });
      }

      const pointGeometry = new THREE.BufferGeometry();
      pointGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      const pointMaterial = new THREE.PointsMaterial({
        color: accent,
        size: 0.09,
        transparent: true,
        opacity: 0.85,
        sizeAttenuation: true,
      });
      const points = new THREE.Points(pointGeometry, pointMaterial);
      scene.add(points);

      const MAX_LINKS = COUNT * 3;
      const linePositions = new Float32Array(MAX_LINKS * 6);
      const lineGeometry = new THREE.BufferGeometry();
      lineGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
      const lineMaterial = new THREE.LineBasicMaterial({
        color: soft,
        transparent: true,
        opacity: 0.28,
      });
      const lines = new THREE.LineSegments(lineGeometry, lineMaterial);
      scene.add(lines);

      const LINK_DISTANCE = 2.6;

      const animate = () => {
        for (let i = 0; i < COUNT; i += 1) {
          positions[i * 3] += velocities[i].x;
          positions[i * 3 + 1] += velocities[i].y;
          positions[i * 3 + 2] += velocities[i].z;
          for (const axis of [0, 1, 2]) {
            const bound = axis === 2 ? 2.2 : axis === 1 ? 3.4 : 5.4;
            if (positions[i * 3 + axis] > bound || positions[i * 3 + axis] < -bound) {
              velocities[i][axis === 0 ? 'x' : axis === 1 ? 'y' : 'z'] *= -1;
            }
          }
        }
        pointGeometry.attributes.position.needsUpdate = true;

        let linkCount = 0;
        for (let i = 0; i < COUNT && linkCount < MAX_LINKS; i += 1) {
          for (let j = i + 1; j < COUNT && linkCount < MAX_LINKS; j += 1) {
            const dx = positions[i * 3] - positions[j * 3];
            const dy = positions[i * 3 + 1] - positions[j * 3 + 1];
            const dz = positions[i * 3 + 2] - positions[j * 3 + 2];
            const distSq = dx * dx + dy * dy + dz * dz;
            if (distSq < LINK_DISTANCE * LINK_DISTANCE) {
              const base = linkCount * 6;
              linePositions[base] = positions[i * 3];
              linePositions[base + 1] = positions[i * 3 + 1];
              linePositions[base + 2] = positions[i * 3 + 2];
              linePositions[base + 3] = positions[j * 3];
              linePositions[base + 4] = positions[j * 3 + 1];
              linePositions[base + 5] = positions[j * 3 + 2];
              linkCount += 1;
            }
          }
        }
        lineGeometry.setDrawRange(0, linkCount * 2);
        lineGeometry.attributes.position.needsUpdate = true;

        scene.rotation.y += 0.0009;
        scene.rotation.x = Math.sin(Date.now() * 0.00004) * 0.08;

        renderer.render(scene, camera);
        frame = window.requestAnimationFrame(animate);
      };
      animate();

      const handleResize = () => {
        if (!mount) return;
        const w = mount.clientWidth || 1;
        const h = mount.clientHeight || 1;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
      };
      window.addEventListener('resize', handleResize);

      cleanup = () => {
        window.removeEventListener('resize', handleResize);
        window.cancelAnimationFrame(frame);
        pointGeometry.dispose();
        pointMaterial.dispose();
        lineGeometry.dispose();
        lineMaterial.dispose();
        renderer.dispose();
        if (renderer.domElement.parentNode === mount) {
          mount.removeChild(renderer.domElement);
        }
      };
    });

    return () => {
      disposed = true;
      cleanup();
    };
  }, [reducedMotion]);

  if (reducedMotion) return null;

  return (
    <div
      ref={mountRef}
      className="hero-canvas"
      aria-hidden="true"
    />
  );
}
