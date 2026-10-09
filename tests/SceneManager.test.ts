import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('three', async (importOriginal) => {
  const actual = await importOriginal<typeof import('three')>();
  return {
    ...actual,
    WebGLRenderer: vi.fn(),
  };
});

import * as THREE from 'three';
import { SceneManager, SceneManagerConfig } from '../src/webgl/SceneManager';

describe('SceneManager (CI/CD Automated Execution Spec v7.0-STRICT)', () => {
  let canvas: HTMLCanvasElement;
  let config: SceneManagerConfig;
  let mockRendererInstance: any;

  const triggerFrame = (manager: SceneManager): void => {
    (manager as any).loop();
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
      info: {
        render: {
          calls: 42,
          triangles: 128,
        },
      },
    };

    // vitest 5+：箭头函数实现不可用于 `new`，须以函数表达式构造 mock 实例
    vi.mocked(THREE.WebGLRenderer).mockImplementation(
      function (this: unknown) {
        return mockRendererInstance;
      } as unknown as typeof THREE.WebGLRenderer,
    );
    vi.mocked(THREE.WebGLRenderer).mockClear();
    mockRendererInstance.render.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('生命周期：挂载与配置初始化', () => {
    it('应基于入参及默认值正确初始化相机与渲染器配置', () => {
      const manager = new SceneManager(config);
      manager.mount();

      expect(THREE.WebGLRenderer).toHaveBeenCalledTimes(1);
      expect(mockRendererInstance.setPixelRatio).toHaveBeenCalledWith(2);
      expect(mockRendererInstance.setSize).toHaveBeenCalledWith(800, 600, false);

      const camera = manager.getCamera();
      expect(camera).not.toBeNull();
      expect(camera?.fov).toBe(45);
      expect(camera?.near).toBe(0.5);
      expect(camera?.far).toBe(500);
      expect(camera?.position.x).toBe(1);
      expect(camera?.position.y).toBe(2);
      expect(camera?.position.z).toBe(3);

      const scene = manager.getScene();
      expect(scene).not.toBeNull();
    });

    it('mount() 必须满足幂等性：重复调用不应二次实例化渲染器', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.mount();

      expect(THREE.WebGLRenderer).toHaveBeenCalledTimes(1);
    });

    it('已销毁实例调用 mount() 应直接阻断且无副作用', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.dispose();
      manager.mount();

      expect(THREE.WebGLRenderer).toHaveBeenCalledTimes(1);
      expect(manager.getRenderer()).toBeNull();
    });
  });

  describe('渲染调度与时间积分断言', () => {
    it('start() 应同步触发首帧渲染，后续帧通过 loop() 驱动', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();

      expect(mockRendererInstance.render).toHaveBeenCalledTimes(1);
      expect(mockRendererInstance.render).toHaveBeenCalledWith(manager.getScene(), manager.getCamera());

      triggerFrame(manager);
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(2);
    });

    it('pause() 应暂停渲染但保持 RAF 调度，resume() 后恢复', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(1);

      manager.pause();
      triggerFrame(manager);
      triggerFrame(manager);
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(1);

      manager.resume();
      triggerFrame(manager);
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(2);
    });

    it('必须严格落实 Delta 钳制硬指标：单帧步进不得超过 MAX_DELTA_SECONDS (0.1s)', () => {
      const manager = new SceneManager(config);
      manager.mount();

      vi.spyOn(THREE.Clock.prototype, 'getDelta').mockReturnValue(5.0);

      let capturedDelta = 0;
      let capturedElapsed = 0;
      manager.onUpdate((delta, elapsed) => {
        capturedDelta = delta;
        capturedElapsed = elapsed;
      });

      manager.start();

      expect(capturedDelta).toBe(0.1);
      expect(capturedElapsed).toBe(0.1);
    });

    it('onUpdate 注销函数必须有效移除监听回调', () => {
      const manager = new SceneManager(config);
      manager.mount();

      const callback = vi.fn();
      const unsubscribe = manager.onUpdate(callback);

      manager.start();
      expect(callback).toHaveBeenCalledTimes(1);

      unsubscribe();
      triggerFrame(manager);
      expect(callback).toHaveBeenCalledTimes(1);
    });

    it('getStats() 应正确读取实时遥测指标', () => {
      const manager = new SceneManager(config);
      manager.mount();
      const stats = manager.getStats();

      expect(stats.drawCalls).toBe(42);
      expect(stats.triangles).toBe(128);
    });
  });

  describe('空间矩阵与视口管线', () => {
    it('resize() 必须同步更新相机视锥宽高比并重置投影矩阵', () => {
      const manager = new SceneManager(config);
      manager.mount();
      const camera = manager.getCamera()!;
      const projSpy = vi.spyOn(camera, 'updateProjectionMatrix');

      manager.resize(1920, 1080);

      expect(camera.aspect).toBe(1920 / 1080);
      expect(projSpy).toHaveBeenCalledTimes(1);
      expect(mockRendererInstance.setSize).toHaveBeenCalledWith(1920, 1080, false);
    });

    it('computeMVP() 必须输出准确的 P * V * M 复合三维空间变换矩阵', () => {
      const manager = new SceneManager(config);
      manager.mount();

      const camera = manager.getCamera()!;
      camera.updateMatrixWorld(true);

      const customModelMatrix = new THREE.Matrix4().makeTranslation(2, 4, 6);
      const computedMVP = manager.computeMVP(customModelMatrix);

      const expectedView = camera.matrixWorldInverse.clone();
      const expectedProj = camera.projectionMatrix.clone();
      const expectedMVP = new THREE.Matrix4().multiplyMatrices(expectedProj, expectedView).multiply(customModelMatrix);

      expect(computedMVP.elements).toEqual(expectedMVP.elements);
    });

    it('未挂载时 computeMVP() 必须降级输出单位矩阵 (Identity)', () => {
      const manager = new SceneManager(config);
      const mvp = manager.computeMVP();
      expect(mvp.elements).toEqual(new THREE.Matrix4().identity().elements);
    });
  });

  describe('硬件上下文丢失与恢复灾备链路', () => {
    it('webglcontextlost 触发时必须阻止默认行为并取消 RAF 调度', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();

      const lostEvent = new Event('webglcontextlost', { cancelable: true });
      const preventDefaultSpy = vi.spyOn(lostEvent, 'preventDefault');

      canvas.dispatchEvent(lostEvent);

      expect(preventDefaultSpy).toHaveBeenCalledTimes(1);
      expect((manager as any).contextLost).toBe(true);
      expect((manager as any).rafId).toBeNull();
    });

    it('webglcontextrestored 触发后必须销毁旧渲染器、重建管线并恢复渲染', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();
      expect(THREE.WebGLRenderer).toHaveBeenCalledTimes(1);

      const lostEvent = new Event('webglcontextlost', { cancelable: true });
      canvas.dispatchEvent(lostEvent);

      const restoredEvent = new Event('webglcontextrestored');
      canvas.dispatchEvent(restoredEvent);

      expect(mockRendererInstance.dispose).toHaveBeenCalledTimes(1);
      expect(THREE.WebGLRenderer).toHaveBeenCalledTimes(2);
      expect((manager as any).contextLost).toBe(false);
    });
  });

  describe('显存安全与注销级联', () => {
    it('dispose() 必须完整释放场景内所有几何体与材质贴图', () => {
      const manager = new SceneManager(config);
      manager.mount();
      const scene = manager.getScene()!;

      const geometry = new THREE.BoxGeometry(1, 1, 1);
      const geomDisposeSpy = vi.spyOn(geometry, 'dispose');

      const texture = new THREE.Texture();
      const texDisposeSpy = vi.spyOn(texture, 'dispose');

      const material = new THREE.MeshStandardMaterial({ map: texture });
      const matDisposeSpy = vi.spyOn(material, 'dispose');

      const mesh = new THREE.Mesh(geometry, material);
      scene.add(mesh);

      manager.dispose();

      expect(geomDisposeSpy).toHaveBeenCalledTimes(1);
      expect(matDisposeSpy).toHaveBeenCalledTimes(1);
      expect(texDisposeSpy).toHaveBeenCalledTimes(1);
      expect(mockRendererInstance.dispose).toHaveBeenCalledTimes(1);
      expect(manager.getScene()).toBeNull();
      expect(manager.getCamera()).toBeNull();
      expect(manager.getRenderer()).toBeNull();
    });

    it('多材质数组 (Material[]) 结构在注销时亦必须被正确遍历释放', () => {
      const manager = new SceneManager(config);
      manager.mount();
      const scene = manager.getScene()!;

      const matA = new THREE.MeshBasicMaterial();
      const matB = new THREE.MeshBasicMaterial();
      const matASpy = vi.spyOn(matA, 'dispose');
      const matBSpy = vi.spyOn(matB, 'dispose');

      const mesh = new THREE.Mesh(new THREE.BufferGeometry(), [matA, matB]);
      scene.add(mesh);

      manager.dispose();

      expect(matASpy).toHaveBeenCalledTimes(1);
      expect(matBSpy).toHaveBeenCalledTimes(1);
    });

    it('重复调用 dispose() 必须具备幂等保护，禁止重复销毁或空指针解引用', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.dispose();

      expect(() => {
        manager.dispose();
      }).not.toThrow();

      expect(mockRendererInstance.dispose).toHaveBeenCalledTimes(1);
    });
  });
});
