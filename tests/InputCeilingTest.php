<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests {
    final class InputCeilingPregSpy
    {
        /** @var int */
        public static $calls = 0;

        /** @var int[] */
        public static $subjectLengths = [];

        /** @var int[] */
        public static $errors = [];
    }

    final class InputCeilingHostSpy
    {
        /** @var int[] */
        public static $trimLengths = [];

        /** @var int[] */
        public static $lowerLengths = [];

        /** @var int[] */
        public static $filterLengths = [];
    }

    use Funnypot\Core\Config;
    use Funnypot\Core\Contracts\CompiledStore;
    use Funnypot\Core\Detection;
    use Funnypot\Core\Honeypot;
    use Funnypot\Core\Observer;
    use Funnypot\Core\RequestContext;
    use Funnypot\Core\SiteProfile;
    use Funnypot\Core\SynthesizedResponse;
    use Funnypot\Core\Template\TemplateAttackEmulator;
    use Funnypot\Core\Verdict;
    use PHPUnit\Framework\TestCase;

    final class InputCeilingTest extends TestCase
    {
        public function test_honeypot_declines_before_store_config_and_observer_work(): void
        {
            $store = new class implements CompiledStore {
                /** @var int */
                public $lookups = 0;

                public function lookup(string $key): ?array
                {
                    $this->lookups++;
                    throw new \RuntimeException('lookup must not run');
                }

                public function template(string $id): ?array
                {
                    throw new \RuntimeException('template must not run');
                }

                public function version(): array
                {
                    return [];
                }
            };
            $configCalls = (object) ['gate' => 0, 'trusted' => 0, 'kill' => 0, 'seed' => 0];
            $config = new Config('respond');
            $config->attackEmulation = true;
            $config->gate = static function (RequestContext $r) use ($configCalls): bool {
                $configCalls->gate++;
                return true;
            };
            $config->trustedBypass = static function (RequestContext $r) use ($configCalls): bool {
                $configCalls->trusted++;
                return false;
            };
            $config->killSwitch = static function () use ($configCalls): bool {
                $configCalls->kill++;
                return false;
            };
            $config->personaSeed = static function (RequestContext $r) use ($configCalls): string {
                $configCalls->seed++;
                return 'seed';
            };
            $observer = new class implements Observer {
                /** @var int */
                public $calls = 0;

                public function onDetection(RequestContext $r, Detection $detection): void
                {
                    $this->calls++;
                }

                public function shouldRespond(RequestContext $r, Detection $detection): bool
                {
                    $this->calls++;
                    return true;
                }

                public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
                {
                    $this->calls++;
                }
            };
            $engine = new Honeypot($store, $config, $observer);
            foreach ([4097, 65536] as $targetBytes) {
                $prefix = '/.git/config';
                $request = new RequestContext('GET', $prefix . str_repeat('x', $targetBytes - strlen($prefix)));

                $verdict = $engine->classify($request, SiteProfile::empty());
                self::assertSame(Verdict::CLEAN, $verdict->classification);
                self::assertTrue($verdict->detection->isEmpty());
                self::assertFalse($engine->detect($request)->matched);
                self::assertNull($engine->respond($request));
            }
            self::assertSame(0, $store->lookups);
            self::assertSame(['gate' => 0, 'trusted' => 0, 'kill' => 0, 'seed' => 0], (array) $configCalls);
            self::assertSame(0, $observer->calls);
        }

        /**
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_every_request_aware_emulator_entry_point_declines_before_regex_or_render(): void
        {
            $this->installPregSpy();
            $rule = [
                'id' => 'bounded-rule',
                'owns_path' => ['/known'],
                'match' => [['in' => 'request', 'regex' => 'known']],
                'response' => ['body' => 'must-not-render', 'headers' => []],
                'status' => 200,
            ];
            $param = [
                'schema' => 1,
                'buckets' => [
                    'known' => [[
                        'id' => 'bounded-param',
                        'regex' => '^/known/(?P<path>.+)$',
                        'response' => ['body' => 'must-not-render', 'headers' => []],
                    ]],
                ],
            ];
            $emulator = new TemplateAttackEmulator([$rule], [], null, null, $param);
            $this->resetPregSpy();
            foreach ([4097, 65536] as $targetBytes) {
                $request = new RequestContext('GET', '/known', str_repeat('q', $targetBytes - strlen('/known') - 1));

                self::assertNull($emulator->matchRule($request));
                self::assertNull($emulator->matchParamRoute($request));
                self::assertNull($emulator->emulate($request));
                self::assertFalse($emulator->ownsPath('/known' . str_repeat('x', $targetBytes - strlen('/known'))));
                self::assertNull($emulator->renderRule($rule, [], 0, $request));
            }
            self::assertSame(0, InputCeilingPregSpy::$calls);
            self::assertSame([], InputCeilingPregSpy::$subjectLengths);
        }

        public function test_exactly_4096_bytes_retain_route_and_emulator_semantics(): void
        {
            $path = '/known';
            $query = str_repeat('q', 4096 - strlen($path) - 1);
            $rule = [
                'id' => 'bounded-rule',
                'match' => [['in' => 'path', 'regex' => '^/known$']],
                'response' => ['body' => 'ok', 'headers' => []],
                'status' => 200,
            ];
            $emulator = new TemplateAttackEmulator([$rule]);

            self::assertNotNull($emulator->matchRule(new RequestContext('GET', $path, $query)));
        }

        /**
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_every_attack_pcre_subject_and_error_is_observed_within_the_window(): void
        {
            $this->installPregSpy();
            $rule = [
                'id' => 'bounded-subject',
                'match' => [['in' => 'request', 'regex' => 'needle']],
                'response' => ['body' => 'ok', 'headers' => []],
                'status' => 200,
            ];
            $this->resetPregSpy();

            $matched = (new TemplateAttackEmulator([$rule]))->matchRule(new RequestContext(
                'POST',
                '/',
                '',
                [],
                str_repeat('%2525', 2000) . 'needle'
            ));

            self::assertNotNull($matched);
            self::assertNotEmpty(InputCeilingPregSpy::$subjectLengths);
            self::assertLessThanOrEqual(32768, max(InputCeilingPregSpy::$subjectLengths));
            self::assertSame(array_fill(0, InputCeilingPregSpy::$calls, PREG_NO_ERROR), InputCeilingPregSpy::$errors);
        }

        /**
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_direct_host_is_capped_before_policy_and_bot_operations(): void
        {
            $this->installHostSpies();
            $seenByPolicy = 0;
            $request = new RequestContext('GET', '/ordinary', '', [
                'User-Agent' => 'curl/8.0',
                'Accept' => '*/*',
                'Accept-Encoding' => 'gzip',
            ], null, str_repeat('H', 1024 * 1024));
            $config = new Config('detect', null, 'matched-only', static function (RequestContext $r) use (&$seenByPolicy): string {
                $seenByPolicy = strlen($r->host);

                return $r->host;
            });

            self::assertSame(512, strlen($request->host));
            $config->seedFor($request);
            self::assertSame(512, $seenByPolicy);

            $store = new class implements CompiledStore {
                public function lookup(string $key): ?array { return null; }
                public function template(string $id): ?array { return null; }
                public function version(): array { return []; }
            };
            (new Honeypot($store, $config))->classify($request, SiteProfile::empty());

            self::assertNotEmpty(InputCeilingHostSpy::$trimLengths);
            self::assertLessThanOrEqual(512, max(InputCeilingHostSpy::$trimLengths));
            self::assertNotEmpty(InputCeilingHostSpy::$lowerLengths);
            self::assertLessThanOrEqual(512, max(InputCeilingHostSpy::$lowerLengths));
            self::assertSame([512], InputCeilingHostSpy::$filterLengths);
        }

        private function resetPregSpy(): void
        {
            InputCeilingPregSpy::$calls = 0;
            InputCeilingPregSpy::$subjectLengths = [];
            InputCeilingPregSpy::$errors = [];
        }

        private function installPregSpy(): void
        {
            eval(<<<'PHP'
namespace Funnypot\Core\Template;
function preg_match($pattern, $subject, &$matches = null, $flags = 0, $offset = 0) {
    \Funnypot\Core\Tests\InputCeilingPregSpy::$calls++;
    \Funnypot\Core\Tests\InputCeilingPregSpy::$subjectLengths[] = strlen($subject);
    $result = \preg_match($pattern, $subject, $matches, $flags, $offset);
    \Funnypot\Core\Tests\InputCeilingPregSpy::$errors[] = \preg_last_error();
    return $result;
}
PHP
            );
        }

        private function installHostSpies(): void
        {
            eval(<<<'PHP'
namespace Funnypot\Core;
function trim($value, $characters = " \t\n\r\0\x0B") {
    \Funnypot\Core\Tests\InputCeilingHostSpy::$trimLengths[] = strlen($value);
    return \trim($value, $characters);
}
function strtolower($value) {
    \Funnypot\Core\Tests\InputCeilingHostSpy::$lowerLengths[] = strlen($value);
    return \strtolower($value);
}
function filter_var($value, $filter = FILTER_DEFAULT, $options = 0) {
    \Funnypot\Core\Tests\InputCeilingHostSpy::$filterLengths[] = strlen($value);
    return \filter_var($value, $filter, $options);
}
PHP
            );
        }
    }
}
