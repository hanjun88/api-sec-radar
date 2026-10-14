import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// 沿用基线测试的 mock 策略：仅替换 WebGLRenderer（jsdom 无 WebGL 上下文），
// 其余 three 逻辑保持真实实现，确保测的是被测代码而非空壳。
vi.mock('three', async (importOriginal) => {
  const actual = await importOriginal<typeof import('three')>();
  return {
    ...actual,
    WebGLRenderer: vi.fn(),
  };
});

import * as THREE from 'three';
import { SceneManager, SceneManagerConfig } from '../src/webgl/SceneManager';

describe('SceneManager 生命周期与显存销毁链深化 (Layer 3)', () => {
  let canvas: HTMLCanvasElement;
  let config: SceneManagerConfig;
  let mockRendererInstance: any;

  const triggerFrame = (manager: SceneManager): void => {
    (manager as any).loop();
  };

  const buildManager = (): SceneManager => {
    const manager = new SceneManager(config);
    manager.mount();
    return manager;
  };

  beforeEach(() => {
    canvas = document.createElement('canvas');
    canvas.width = 800;
    canvas.height = 600;

    config = {
      canvas,
      width: 800,
      height: 600,
      pixelRatio: 2,
      antialias: true,
      alpha: true,
      cameraFov: 45,
      cameraNear: 0.5,
      cameraFar: 500,
      cameraPosition: [1, 2, 3],
    };

    mockRendererInstance = {
      setPixelRatio: vi.fn(),
      setSize: vi.fn(),
      render: vi.fn(),
      dispose: vi.fn(),
      outputColorSpace: THREE.SRGBColorSpace,
      toneMapping: THREE.ACESFilmicToneMapping,
      toneMappingExposure: 1.0,
      info: { render: { calls: 42, triangles: 128 } },
    };

    vi.mocked(THREE.WebGLRenderer).mockImplementation(() => mockRendererInstance);
    vi.mocked(THREE.WebGLRenderer).mockClear();
    mockRendererInstance.render.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('资源销毁链：11 级纹理槽位 + 递归子节点', () => {
    it('必须递归销毁多层级 (Scene→Group→Group→Mesh) 中的 geometry/material/texture', () => {
      const manager = buildManager();
      const scene = manager.getScene()!;

      const geometry = new THREE.BoxGeometry(1, 1, 1);
      const texture = new THREE.Texture();
      const material = new THREE.MeshStandardMaterial({ map: texture });
      const geomSpy = vi.spyOn(geometry, 'dispose');
      const matSpy = vi.spyOn(material, 'dispose');
      const texSpy = vi.spyOn(texture, 'dispose');

      const leafMesh = new THREE.Mesh(geometry, material);
      const childGroup = new THREE.Group();
      const rootGroup = new THREE.Group();
      childGroup.add(leafMesh);
      rootGroup.add(childGroup);
      scene.add(rootGroup);

      manager.dispose();

      expect(geomSpy).toHaveBeenCalledTimes(1);
      expect(matSpy).toHaveBeenCalledTimes(1);
      expect(texSpy).toHaveBeenCalledTimes(1);
    });

    it('必须逐一销毁材质上全部 11 个纹理槽位 (map/normalMap/.../lightMap)', () => {
      const manager = buildManager();
      const scene = manager.getScene()!;

      const textureKeys = [
        'map', 'normalMap', 'roughnessMap', 'metalnessMap',
        'aoMap', 'emissiveMap', 'alphaMap', 'envMap',
        'bumpMap', 'displacementMap', 'lightMap',
      ] as const;

      const material = new THREE.MeshStandardMaterial();
      const spies = textureKeys.map((key) => {
        const tex = new THREE.Texture();
        (material as any)[key] = tex;
        return vi.spyOn(tex, 'dispose');
      });

      scene.add(new THREE.Mesh(new THREE.BufferGeometry(), material));
      manager.dispose();

      spies.forEach((spy, i) => {
        expect(spy, `texture slot "${textureKeys[i]}" 未被 dispose`).toHaveBeenCalledTimes(1);
      });
    });

    it('InstancedMesh 必须释放 instanceMatrix/instanceColor 实例缓冲 (调用其 dispose)', () => {
      const manager = buildManager();
      const scene = manager.getScene()!;

      const instanced = new THREE.InstancedMesh(
        new THREE.SphereGeometry(0.12, 16, 16),
        new THREE.MeshStandardMaterial(),
        128,
      );
      const instDisposeSpy = vi.spyOn(instanced, 'dispose');
      const geomSpy = vi.spyOn(instanced.geometry, 'dispose');
      const matSpy = vi.spyOn(instanced.material as THREE.Material, 'dispose');

      scene.add(instanced);
      manager.dispose();

      // InstancedMesh.dispose() 会 dispatch 'dispose'，渲染器据此从 WebGLAttributes 移除
      // instanceMatrix / instanceColor，否则这两块实例缓冲将泄漏显存。
      expect(instDisposeSpy).toHaveBeenCalledTimes(1);
      expect(geomSpy).toHaveBeenCalledTimes(1);
      expect(matSpy).toHaveBeenCalledTimes(1);
    });

    it('重复 dispose 必须幂等：每个资源仅销毁一次且不抛异常', () => {
      const manager = buildManager();
      const scene = manager.getScene()!;

      const geometry = new THREE.BoxGeometry(1, 1, 1);
      const texture = new THREE.Texture();
      const material = new THREE.MeshStandardMaterial({ map: texture });
      const geomSpy = vi.spyOn(geometry, 'dispose');
      const matSpy = vi.spyOn(material, 'dispose');
      const texSpy = vi.spyOn(texture, 'dispose');

      scene.add(new THREE.Mesh(geometry, material));

      manager.dispose();
      expect(() => manager.dispose()).not.toThrow();

      expect(geomSpy).toHaveBeenCalledTimes(1);
      expect(matSpy).toHaveBeenCalledTimes(1);
      expect(texSpy).toHaveBeenCalledTimes(1);
      expect(mockRendererInstance.dispose).toHaveBeenCalledTimes(1);
    });

    it('dispose 后必须清空内部引用，杜绝残留导致的隐性内存泄漏', () => {
      const manager = buildManager();
      manager.onUpdate(() => { /* noop */ });

      manager.dispose();

      expect(manager.getScene()).toBeNull();
      expect(manager.getCamera()).toBeNull();
      expect(manager.getRenderer()).toBeNull();
      expect((manager as any).updateCallbacks).toHaveLength(0);
      expect((manager as any).rafId).toBeNull();
      expect((manager as any).mounted).toBe(false);
    });

    it('未 mount 的空实例直接 dispose 应安全 (不创建 renderer)', () => {
      const manager = new SceneManager(config);

      expect(() => manager.dispose()).not.toThrow();
      expect(THREE.WebGLRenderer).not.toHaveBeenCalled();
      expect(mockRendererInstance.dispose).not.toHaveBeenCalled();
    });

    it('空场景 (无子节点) dispose 应安全完成', () => {
      const manager = buildManager();
      expect(() => manager.dispose()).not.toThrow();
      expect(mockRendererInstance.dispose).toHaveBeenCalledTimes(1);
    });
  });

  describe('生命周期状态机边界', () => {
    it('mount 前调用各方法必须安全降级 (不抛异常)', () => {
      const manager = new SceneManager(config);

      expect(() => {
        manager.start();
        manager.pause();
        manager.resume();
        manager.resize(100, 100);
        manager.getStats();
        manager.computeMVP();
        manager.onUpdate(() => { /* noop */ });
      }).not.toThrow();

      expect(manager.getStats()).toEqual({ drawCalls: 0, triangles: 0 });
      expect(manager.computeMVP().elements).toEqual(new THREE.Matrix4().identity().elements);
    });

    it('dispose 后调用 start/resume/resize/mount/onUpdate 均安全且无副作用', () => {
      const manager = buildManager();
      manager.dispose();

      expect(() => {
        manager.start();
        manager.resume();
        manager.resize(100, 100);
        manager.mount();
        manager.onUpdate(() => { /* noop */ });
      }).not.toThrow();

      expect(THREE.WebGLRenderer).toHaveBeenCalledTimes(1); // mount() 不应重建 renderer
      expect(mockRendererInstance.render).not.toHaveBeenCalled();
      expect(manager.getRenderer()).toBeNull();
    });

    it('dispose 后 start 不应再触发渲染', () => {
      const manager = buildManager();
      manager.start();
      mockRendererInstance.render.mockClear();

      manager.dispose();
      manager.start();
      triggerFrame(manager);

      expect(mockRendererInstance.render).not.toHaveBeenCalled();
    });

    it('省略可选配置时应回落到默认相机参数与默认 pixelRatio', () => {
      const manager = new SceneManager({ canvas, width: 640, height: 480 });
      manager.mount();

      const cam = manager.getCamera()!;
      expect(cam.fov).toBe(50);
      expect(cam.near).toBe(0.1);
      expect(cam.far).toBe(100);
      expect(cam.position.toArray()).toEqual([0, 6, 8]);
      expect(mockRendererInstance.setPixelRatio).toHaveBeenCalledWith(1);
    });

    it('resize 传入 0 尺寸边界不应抛异常', () => {
      const manager = buildManager();
      expect(() => manager.resize(0, 0)).not.toThrow();
    });
  });
});
