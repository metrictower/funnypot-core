<?php

declare(strict_types=1);

/**
 * Shared model catalog for the fake AI-inference API surfaces (Ollama /api/tags,
 * /api/ps, /api/show; OpenAI-compatible /v1/models; Anthropic-compatible
 * /v1/models). Every advertised model NAME below is a real, currently-shipping
 * model — verified against ollama.com/library and the vendor's Hugging Face org
 * on 2026-08-23. Sizes, digests, and vram/expiry timestamps are fabricated (a
 * real weight file's exact bytes are never public, so faking them carries no
 * fingerprint risk) but shaped to be plausible for the real parameter count.
 *
 * Verified sources (checked 2026-08-23):
 *  - kimi-k3           https://ollama.com/library/kimi-k3            (Moonshot AI, 2.8T MoE, 1M ctx)
 *  - qwen3:235b        https://ollama.com/library/qwen3              (Alibaba/Qwen, 235B-A22B MoE, 256K ctx)
 *  - glm-4.6           https://ollama.com/library/glm-4.6            (Z.ai/Zhipu, 355B-A32B MoE, 200K ctx)
 *                      https://huggingface.co/zai-org/GLM-4.6
 *  - deepseek-v3.2     https://ollama.com/library/deepseek-v3.2      (DeepSeek, 671B-A37B MoE, 160K ctx)
 *  - mistral-large     https://ollama.com/library/mistral-large      (Mistral AI, 123B dense, 128K ctx)
 *  - nemotron-3-super  https://ollama.com/library/nemotron-3-super   (NVIDIA, 120B-A12B MoE, 256K ctx)
 *  - gpt-oss:120b      https://ollama.com/library/gpt-oss            (OpenAI, 120B MoE, MXFP4, 128K ctx)
 *  - gemma3:27b        https://ollama.com/library/gemma3             (Google, 27B dense, 128K ctx)
 *
 * "big-pickle" is the one intentional exception to the "real, verified model" rule
 * above: it's an OpenCode Zen router alias with no public weights, advertised as an
 * exotic/premium rig headline. Its vendor/size/param count are fabricated like every
 * other non-name field. Appended last so callers that key off the first entry still
 * land on a verified model.
 */

return [
    [
        'name' => 'kimi-k3:2.8t',
        'openai_id' => 'kimi-k3',
        'display_name' => 'Kimi K3',
        'owned_by' => 'moonshotai',
        'size' => 1780000000000,
        'digest' => '541dc907f944c34646137387c114442d842fff71b476dffe0db5e0f78931f8e2',
        'family' => 'kimi',
        'families' => ['kimi'],
        'parameter_size' => '2.8T',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 1048576,
    ],
    [
        'name' => 'qwen3:235b',
        'openai_id' => 'qwen3-235b',
        'display_name' => 'Qwen3 235B',
        'owned_by' => 'qwen',
        'size' => 142000000000,
        'digest' => '52a4cdafc54280f1d691038ad56c70803af9573c7495db5209b8df71963d661d',
        'family' => 'qwen3',
        'families' => ['qwen3'],
        'parameter_size' => '235B',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 262144,
    ],
    [
        'name' => 'glm-4.6:355b',
        'openai_id' => 'glm-4.6',
        'display_name' => 'GLM-4.6',
        'owned_by' => 'zai-org',
        'size' => 227000000000,
        'digest' => '3cb6d03b68f8d11c850e3a17fc5c93a3cfa25d075e14ee638ddcd14cb0e4955a',
        'family' => 'glm4',
        'families' => ['glm4'],
        'parameter_size' => '355B',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 204800,
    ],
    [
        'name' => 'deepseek-v3.2:671b',
        'openai_id' => 'deepseek-v3.2',
        'display_name' => 'DeepSeek V3.2',
        'owned_by' => 'deepseek-ai',
        'size' => 404000000000,
        'digest' => '8e5d9d98484a2e2292879b0edf86029b9b3da08c10d980b123b35a077f5720eb',
        'family' => 'deepseek2',
        'families' => ['deepseek2'],
        'parameter_size' => '671B',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 163840,
    ],
    [
        'name' => 'mistral-large:123b',
        'openai_id' => 'mistral-large',
        'display_name' => 'Mistral Large',
        'owned_by' => 'mistralai',
        'size' => 73000000000,
        'digest' => 'd9ab4500cf1bda01354e6171e05dd2f772839e87a35a63467488aa9ef1458c09',
        'family' => 'mistral',
        'families' => ['mistral'],
        'parameter_size' => '123B',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 131072,
    ],
    [
        'name' => 'nemotron-3-super:120b',
        'openai_id' => 'nemotron-3-super',
        'display_name' => 'Nemotron 3 Super',
        'owned_by' => 'nvidia',
        'size' => 72000000000,
        'digest' => '26f5f7d6af9d510c4c518a154ea57867e647d643f6d84c1dfbbc59c09bee94cf',
        'family' => 'nemotron',
        'families' => ['nemotron'],
        'parameter_size' => '120B',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 262144,
    ],
    [
        'name' => 'gpt-oss:120b',
        'openai_id' => 'gpt-oss-120b',
        'display_name' => 'GPT-OSS 120B',
        'owned_by' => 'openai',
        'size' => 65000000000,
        'digest' => '48545ebe6944bfa74944583d79ba9c95efb2f764b9cf04ed40e9e7e9e97179f9',
        'family' => 'gptoss',
        'families' => ['gptoss'],
        'parameter_size' => '120B',
        'quantization_level' => 'MXFP4',
        'context_length' => 131072,
    ],
    [
        'name' => 'gemma3:27b',
        'openai_id' => 'gemma-3-27b',
        'display_name' => 'Gemma 3 27B',
        'owned_by' => 'google',
        'size' => 17000000000,
        'digest' => '3599665e02e3136eaf4bd9eccf6637c08490bbc1239292d70a3261bb21c5056a',
        'family' => 'gemma3',
        'families' => ['gemma3'],
        'parameter_size' => '27B',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 131072,
    ],
    [
        'name' => 'big-pickle:1.5t',
        'openai_id' => 'big-pickle',
        'display_name' => 'Big Pickle',
        'owned_by' => 'opencode-zen',
        'size' => 1520000000000,
        'digest' => 'b1c47f0a2e8d3c6b5a04f19e72d8c3b6a0f5e2d7c4b1a8f36e0d5c2b7a4f18e63',
        'family' => 'pickle',
        'families' => ['pickle'],
        'parameter_size' => '1.5T',
        'quantization_level' => 'Q4_K_M',
        'context_length' => 262144,
    ],
];
