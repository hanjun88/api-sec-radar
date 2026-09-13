import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as THREE from 'three';
import { SceneManager, SceneManagerConfig } from '../src/webgl/SceneManager';

describe('SceneManager (CI/CD Automated Execution Spec v7.0-STRICT)', () => {
  let canvas: HTMLCanvasElement;
  let config: SceneManagerConfig;
  let mockRendererInstance: any;
  let rendererSpy: any;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(performance, 'now').mockReturnValue(1000);

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

    rendererSpy = vi.spyOn(THREE, 'WebGLRenderer').mockImplementation(() => mockRendererInstance);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('生命周期：挂载与配置初始化', () => {
    it('应基于入参及默认值正确初始化相机与渲染器配置', () => {
      const manager = new SceneManager(config);
      manager.mount();

      expect(rendererSpy).toHaveBeenCalledTimes(1);
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
      expect(scene?.children.length).toBeGreaterThanOrEqual(2);
    });

    it('mount() 必须满足幂等性：重复调用不应二次实例化渲染器', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.mount();

      expect(rendererSpy).toHaveBeenCalledTimes(1);
    });

    it('已销毁实例调用 mount() 应直接阻断且无副作用', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.dispose();
      manager.mount();

      expect(rendererSpy).toHaveBeenCalledTimes(1);
      expect(manager.getRenderer()).toBeNull();
    });
  });

  describe('渲染调度与时间积分断言', () => {
    it('start() 触发后应调度 RAF 循环并调用渲染管线', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();

      expect(mockRendererInstance.render).not.toHaveBeenCalled();

      vi.spyOn(performance, 'now').mockReturnValue(1016);
      vi.advanceTimersByTime(16);

      expect(mockRendererInstance.render).toHaveBeenCalledTimes(1);
      expect(mockRendererInstance.render).toHaveBeenCalledWith(manager.getScene(), manager.getCamera());
    });

    it('pause() 与 resume() 应正确控制帧调度状态转移', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();

      vi.advanceTimersByTime(16);
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(1);

      manager.pause();
      vi.advanceTimersByTime(32);
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(1);

      manager.resume();
      vi.advanceTimersByTime(16);
      expect(mockRendererInstance.render).toHaveBeenCalledTimes(2);
    });

    it('必须严格落实 Delta 钳制硬指标：单帧跳变不得超过 MAX_DELTA_SECONDS (0.1s)', () => {
      const manager = new SceneManager(config);
      manager.mount();

      let capturedDelta = 0;
      let capturedElapsed = 0;
      manager.onUpdate((delta, elapsed) => {
        capturedDelta = delta;
        capturedElapsed = elapsed;
      });

      manager.start();

      vi.spyOn(performance, 'now').mockReturnValue(6000);
      vi.advanceTimersByTime(5000);

      expect(capturedDelta).toBe(0.1);
      expect(capturedElapsed).toBe(0.1);
    });

    it('onUpdate 注销函数必须有效移除监听回调', () => {
      const manager = new SceneManager(config);
      manager.mount();

      const callback = vi.fn();
      const unsubscribe = manager.onUpdate(callback);

      manager.start();
      vi.advanceTimersByTime(16);
      expect(callback).toHaveBeenCalledTimes(1);

      unsubscribe();
      vi.advanceTimersByTime(16);
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
    it('webglcontextlost 触发时必须阻止默认行为并暂停渲染循环', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();

      const lostEvent = new Event('webglcontextlost', { cancelable: true });
      const preventDefaultSpy = vi.spyOn(lostEvent, 'preventDefault');

      canvas.dispatchEvent(lostEvent);

      expect(preventDefaultSpy).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(16);
      expect(mockRendererInstance.render).not.toHaveBeenCalled();
    });

    it('webglcontextrestored 触发后必须销毁旧渲染器、重建管线并自愈恢复调度', () => {
      const manager = new SceneManager(config);
      manager.mount();
      manager.start();

      const lostEvent = new Event('webglcontextlost', { cancelable: true });
      canvas.dispatchEvent(lostEvent);
      expect(rendererSpy).toHaveBeenCalledTimes(1);

      const restoredEvent = new Event('webglcontextrestored');
      canvas.dispatchEvent(restoredEvent);

      expect(mockRendererInstance.dispose).toHaveBeenCalledTimes(1);
      expect(rendererSpy).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(16);
      expect(mockRendererInstance.render).toHaveBeenCalled();
    });
  });

  describe('显存安全与注销级联', () => {
    it('dispose() 必须完整释放场景内所有几何体与 8 类标准材质贴图', () => {
      const manager = new SceneManager(config);
      manager.mount();
      const scene = manager.getScene()!;

      const geometry = new THREE.BoxGeometry(1, 1, 1);
      const geomDisposeSpy = vi.spyOn(geometry, 'dispose');

      const mockTextures: Record<string, THREE.Texture> = {
        map: new THREE.Texture(),
        normalMap: new THREE.Texture(),
        roughnessMap: new THREE.Texture(),
        metalnessMap: new THREE.Texture(),
        aoMap: new THREE.Texture(),
        emissiveMap: new THREE.Texture(),
        alphaMap: new THREE.Texture(),
        envMap: new THREE.Texture(),
      };

      const textureDisposeSpies = Object.values(mockTextures).map((tex) =>
        vi.spyOn(tex, 'dispose')
      );

      const material = new THREE.MeshStandardMaterial({
        map: mockTextures.map,
        normalMap: mockTextures.normalMap,
        roughnessMap: mockTextures.roughnessMap,
        metalnessMap: mockTextures.metalnessMap,
        aoMap: mockTextures.aoMap,
        emissiveMap: mockTextures.emissiveMap,
        alphaMap: mockTextures.alphaMap,
        envMap: mockTextures.envMap,
      });
      const matDisposeSpy = vi.spyOn(material, 'dispose');

      const mesh = new THREE.Mesh(geometry, material);
      scene.add(mesh);

      manager.dispose();

      expect(geomDisposeSpy).toHaveBeenCalledTimes(1);
      expect(matDisposeSpy).toHaveBeenCalledTimes(1);
      textureDisposeSpies.forEach((spy) => {
        expect(spy).toHaveBeenCalledTimes(1);
      });

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
