<?php
namespace LosReCaptcha\Captcha;

use Traversable;
use LosReCaptcha\Service\ReCaptcha as ReCaptchaService;
use Zend\Stdlib\ArrayUtils;
use Zend\Captcha\AbstractAdapter;

/**
 * ReCaptcha v2 adapter
 *
 * Allows to insert captchas driven by ReCaptcha service
 *
 * @see http://recaptcha.net/apidocs/captcha/
 */
class ReCaptcha extends AbstractAdapter
{

    /**
     * Constructor
     *
     * @param null|array|Traversable $options
     */
    public function __construct($options = null)
    {
        $this->service = new ReCaptchaService($options['site_key'], $options['secret_key']);

        if ($options instanceof Traversable) {
            $options = ArrayUtils::iteratorToArray($options);
        }

        if (isset($this->messageTemplates)) {
            $this->abstractOptions['messageTemplates'] = $this->messageTemplates;
        }

        if (isset($this->messageVariables)) {
            $this->abstractOptions['messageVariables'] = $this->messageVariables;
        }

        if (is_array($options)) {
            $this->setOptions($options);
        }
    }

    /**
     * Validate captcha
     *
     * @see \Zend\Validator\ValidatorInterface::isValid()
     * @param mixed $value
     * @param mixed $context
     * @return bool
     */
    public function isValid($value, $context = null)
    {
        if (!is_array($value) && !is_array($context)) {
            $this->error(self::MISSING_VALUE);
            return false;
        }

        if (!is_array($value) && is_array($context)) {
            $value = $context;
        }

        if (empty($value[$this->RESPONSE])) {
            $this->error(self::MISSING_VALUE);
            return false;
        }

        $service = $this->getService();

        $res = $service->verify($value[$this->RESPONSE]);
        if (! $res) {
            $this->error(self::ERR_CAPTCHA);
            return false;
        }

        if (! $res->isValid()) {
            $this->error(self::BAD_CAPTCHA, $res->getErrorCode());
            $service->setParam('error', $res->getErrorCode());
            return false;
        }

        return true;
    }

    /**
     * Get helper name used to render captcha
     *
     * @return string
     */
    public function getHelperName()
    {
        return "losrecaptcha/recaptcha";
    }

    /**
     * {@inheritDoc}
     * @see \Zend\Captcha\AdapterInterface::generate()
     */
    public function generate()
    {
        return '';
    }

}
