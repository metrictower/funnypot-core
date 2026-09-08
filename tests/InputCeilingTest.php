<?php

declare(strict_types=1);

namespace Funnypot\Core\Template {
    final class InputCeilingPregSpy
    {
        /** @var int */
        public static $calls = 0;

        /** @var int[] */
        public static $subjectLengths = [];

        /** @var int[] */
        public static $errors = [];
    }

    function preg_match($pattern, $subject, &$matches = null, $flags = 0, $offset = 0)
    {
        InputCeilingPregSpy::$calls++;
        InputCeilingPregSpy::$subjectLengths[] = strlen($subject);
        $result = \preg_match($pattern, $subject, $matches, $flags, $offset);
        InputCeilingPregSpy::$errors[] = \preg_last_error();

        return $result;
    }
}

namespace Funnypot\Core\Tests {
    use Funnypot\Core\Config;
    use Funnypot\Core\Contracts\CompiledStore;
    use Funnypot\Core\Detection;
    use Funnypot\Core\Honeypot;
    use Funnypot\Core\Observer;
    use Funnypot\Core\RequestContext;
    use Funnypot\Core\SiteProfile;
    use Funnypot\Core\SynthesizedResponse;
    use Funnypot\Core\Template\InputCeilingPregSpy;
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
            $request = new RequestContext('GET', '/.git/config' . str_repeat('x', 4097));

            $verdict = $engine->classify($request, SiteProfile::empty());
            self::assertSame(Verdict::CLEAN, $verdict->classification);
            self::assertTrue($verdict->detection->isEmpty());
            self::assertFalse($engine->detect($request)->matched);
            self::assertNull($engine->respond($request));
            self::assertSame(0, $store->lookups);
            self::assertSame(['gate' => 0, 'trusted' => 0, 'kill' => 0, 'seed' => 0], (array) $configCalls);
            self::assertSame(0, $observer->calls);
        }

        public function test_every_request_aware_emulator_entry_point_declines_before_regex_or_render(): void
        {
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
            $request = new RequestContext('GET', '/known', str_repeat('q', 4091));
            InputCeilingPregSpy::$calls = 0;
            InputCeilingPregSpy::$subjectLengths = [];
            InputCeilingPregSpy::$errors = [];

            self::assertNull($emulator->matchRule($request));
            self::assertNull($emulator->matchParamRoute($request));
            self::assertNull($emulator->emulate($request));
            self::assertFalse($emulator->ownsPath('/known' . str_repeat('x', 4096)));
            self::assertNull($emulator->renderRule($rule, [], 0, $request));
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
            self::assertGreaterThan(0, InputCeilingPregSpy::$calls);
        }

        public function test_every_attack_pcre_subject_and_error_is_observed_within_the_window(): void
        {
            $rule = [
                'id' => 'bounded-subject',
                'match' => [['in' => 'request', 'regex' => 'needle']],
                'response' => ['body' => 'ok', 'headers' => []],
                'status' => 200,
            ];
            InputCeilingPregSpy::$calls = 0;
            InputCeilingPregSpy::$subjectLengths = [];
            InputCeilingPregSpy::$errors = [];

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
    }
}
