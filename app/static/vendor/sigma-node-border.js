// @sigma/node-border, rewritten from its ES module by ./logstotal vendor:update.
(function () {
const { numberToGLSLFloat, sdfCircle } = window.Sigma.rendering;
const { colorToVec4 } = window.Sigma.utils;
const { arrayProp, numberProp, colorProp, enumProp, booleanProp } = window.Sigma.primitives;

function _arrayLikeToArray(r, a) {
  (null == a || a > r.length) && (a = r.length);
  for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e];
  return n;
}

function _arrayWithoutHoles(r) {
  if (Array.isArray(r)) return _arrayLikeToArray(r);
}

function _iterableToArray(r) {
  if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r);
}

function _unsupportedIterableToArray(r, a) {
  if (r) {
    if ("string" == typeof r) return _arrayLikeToArray(r, a);
    var t = {}.toString.call(r).slice(8, -1);
    return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0;
  }
}

function _nonIterableSpread() {
  throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
}

function _toConsumableArray(r) {
  return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread();
}

function _typeof(o) {
  "@babel/helpers - typeof";

  return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) {
    return typeof o;
  } : function (o) {
    return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o;
  }, _typeof(o);
}

/**
 * Border item type extracted from options.
 */

/**
 * Type guards for border color variants
 */
function isAttributeColor(color) {
  return _typeof(color) === "object" && color !== null && "attribute" in color;
}
function isFixedColor(color) {
  return typeof color === "string";
}

/**
 * Type guards for border size variants
 */
function isAttributeSize(size) {
  return _typeof(size) === "object" && size !== null && "attribute" in size;
}

/**
 * Generates the GLSL code for the border layer function.
 * Uses the global `context` struct for context (sdf, shapeSize, aaWidth, pixelSize).
 */
function generateBorderGLSL(borders) {
  var fillCount = borders.filter(function (b) {
    return b.fill;
  }).length;
  var fillCountGLSL = numberToGLSLFloat(fillCount || 1); // Avoid division by zero

  // Generate size calculation code (using context.shapeSize and context.pixelSize)
  var sizeCalculations = borders.flatMap(function (border, i) {
    if (border.fill) return [];
    var size = border.size,
      mode = border.mode;
    var isPixelMode = mode === "pixels";

    // Determine value based on size type
    var value;
    if (isAttributeSize(size)) {
      value = "v_borderSize_".concat(i + 1);
    } else {
      value = numberToGLSLFloat(typeof size === "number" ? size : 0);
    }

    // For relative mode: multiply by context.shapeHalfSize (size is a fraction 0-1 of the shape)
    // For pixels mode: convert pixels to UV space using context.pixelToUV
    if (isPixelMode) {
      return ["  float borderSize_".concat(i + 1, " = ").concat(value, " * context.pixelToUV;")];
    } else {
      return ["  float borderSize_".concat(i + 1, " = context.shapeHalfSize * ").concat(value, ";")];
    }
  }).join("\n");

  // Generate non-fill size sum for fill calculation
  var nonFillSizes = borders.flatMap(function (b, i) {
    return !b.fill ? ["borderSize_".concat(i + 1)] : [];
  }).join(" + ");
  var nonFillSizesExpr = nonFillSizes || "0.0";

  // Generate fill border sizes
  var fillSizeCalculations = borders.flatMap(function (b, i) {
    return b.fill ? ["  float borderSize_".concat(i + 1, " = fillBorderSize;")] : [];
  }).join("\n");

  // Generate cumulative boundary calculations (from outside to inside)
  // In SDF space: boundary_0 = 0.0 (shape edge), boundaries go negative (inside)
  var boundaryCalculations = borders.map(function (_, i) {
    return "  float boundary_".concat(i + 1, " = boundary_").concat(i, " - borderSize_").concat(i + 1, ";");
  }).join("\n");

  // Generate color assignments
  var colorAssignments = borders.map(function (_ref, i) {
    var color = _ref.color;
    if (isAttributeColor(color)) {
      return "  vec4 borderColor_".concat(i + 1, " = v_borderColor_").concat(i + 1, ";");
    } else {
      // Fixed color string - use uniform
      return "  vec4 borderColor_".concat(i + 1, " = u_borderColor_").concat(i + 1, ";");
    }
  }).join("\n");

  // Generate color adjustments (bias and skip tiny borders)
  // Use 2.0 * context.aaWidth as threshold to match internal AA band width
  // For the first border (i=0), fall back to itself (no borderColor_0)
  var colorAdjustments = borders.map(function (_, i) {
    return "  borderColor_".concat(i + 1, ".a *= bias;\n  if (borderSize_").concat(i + 1, " <= 2.0 * context.aaWidth) { borderColor_").concat(i + 1, " = ").concat(i === 0 ? "borderColor_1" : "borderColor_".concat(i), "; }");
  }).join("\n");

  // Generate the color selection logic with antialiasing
  // In SDF space: context.sdf > 0 means outside, context.sdf < 0 means inside
  // boundary_0 = 0.0, boundary_1 = -borderSize_1, etc.
  var colorSelection = borders.map(function (_, i) {
    if (i === 0) {
      // First border: no AA at outer edge (generator handles that)
      // Solid color from shape edge (sdf=0) down to boundary_1
      return "if (context.sdf > boundary_1) {\n    color = borderColor_1;\n  } else ";
    } else {
      // Internal borders: AA transition between border colors using 2x context.aaWidth
      // The AA band spans from boundary_i to boundary_i - 2*aaWidth
      return "if (context.sdf > boundary_".concat(i, " - 2.0 * context.aaWidth) {\n    color = mix(borderColor_").concat(i + 1, ", borderColor_").concat(i, ", (context.sdf - boundary_").concat(i, " + 2.0 * context.aaWidth) / (2.0 * context.aaWidth));\n  } else if (context.sdf > boundary_").concat(i + 1, ") {\n    color = borderColor_").concat(i + 1, ";\n  } else ");
    }
  }).join("");

  // Build function parameters: attributes first (as varyings), then uniforms
  // This order must match what the generator produces in generator.ts
  var attributeParams = [].concat(_toConsumableArray(borders.flatMap(function (_ref2, i) {
    var color = _ref2.color;
    return isAttributeColor(color) ? ["vec4 v_borderColor_".concat(i + 1)] : [];
  })), _toConsumableArray(borders.flatMap(function (_ref3, i) {
    var size = _ref3.size;
    return isAttributeSize(size) ? ["float v_borderSize_".concat(i + 1)] : [];
  })));
  var uniformParams = borders.flatMap(function (_ref4, i) {
    var color = _ref4.color;
    return isFixedColor(color) ? ["vec4 u_borderColor_".concat(i + 1)] : [];
  });

  // Combine all params with proper formatting
  var allParams = [].concat(_toConsumableArray(attributeParams), _toConsumableArray(uniformParams)).join(", ");

  // Check if the first border uses an attribute (dynamic size)
  var firstBorderUsesAttribute = isAttributeSize(borders[0].size);

  // Build the complete GLSL function
  // Context (sdf, shapeSize, aaWidth, pixelSize) accessed via global context struct
  // language=GLSL
  var glsl = /*glsl*/"\nvec4 layer_border(".concat(allParams, ") {\n  const float bias = 255.0 / 254.0;\n\n  // Calculate border sizes (using context.shapeSize and context.pixelSize)\n").concat(sizeCalculations, "\n").concat(firstBorderUsesAttribute ? "\n  // Early return if first border size is effectively zero (layer disabled)\n  if (borderSize_1 <= context.aaWidth) {\n    return vec4(0.0);\n  }\n" : "", "\n  // Calculate fill border size (distribute remaining space)\n  // Use inradiusFactor to get actual shape depth from the bounding size\n  // For circle/square (inradiusFactor=1.0), this equals shapeSize\n  // For triangle (inradiusFactor=0.5), this is half of shapeSize\n  float shapeDepth = context.shapeSize * context.inradiusFactor;\n  float fillBorderSize = (shapeDepth - (").concat(nonFillSizesExpr, ")) / ").concat(fillCountGLSL, ";\n").concat(fillSizeCalculations, "\n\n  // Calculate cumulative boundaries (from outside to inside in SDF space)\n  float boundary_0 = 0.0;  // Shape edge at context.sdf=0\n").concat(boundaryCalculations, "\n\n  // Set up colors\n").concat(colorAssignments, "\n").concat(colorAdjustments, "\n\n  // Select color based on SDF position with antialiasing\n  // Note: outer edge AA (context.sdf > 0 transition) is handled by the composed generator's smoothstep\n  vec4 color = vec4(0.0);\n  ").concat(colorSelection, "{ color = borderColor_").concat(borders.length, "; }\n\n  return color;\n}\n");
  return glsl;
}

/**
 * Creates a border layer that renders one or more concentric borders around a shape.
 * The borders follow the contour of whatever SDF shape is used.
 *
 * @param options - Border configuration options
 * @returns FragmentLayer definition
 *
 * @example
 * ```typescript
 * // Simple border with fill
 * const borderLayer = layerBorder({
 *   borders: [
 *     { size: 0.1, color: { attribute: "borderColor" }, mode: "relative" },
 *     { size: 0, color: { attribute: "color" }, fill: true },
 *   ],
 * });
 *
 * // Use with createNodeProgram
 * const program = createNodeProgram({
 *   shapes: [sdfSquare({ cornerRadius: 0.1 })],
 *   layers: [borderLayer],
 * });
 * ```
 */
function layerBorder(options) {
  var _options$borders;
  var borders = (_options$borders = options === null || options === void 0 ? void 0 : options.borders) !== null && _options$borders !== void 0 ? _options$borders : [];
  if (borders.length === 0) {
    // Return a no-op layer if no borders defined
    return {
      name: "border",
      uniforms: [],
      attributes: [],
      glsl: "vec4 layer_border() { return vec4(0.0); }"
    };
  }
  var _WebGL2RenderingConte = WebGL2RenderingContext,
    UNSIGNED_BYTE = _WebGL2RenderingConte.UNSIGNED_BYTE,
    FLOAT = _WebGL2RenderingConte.FLOAT;

  // Generate uniforms for fixed-value colors (direct string values)
  var uniforms = borders.flatMap(function (_ref5, i) {
    var color = _ref5.color;
    return isFixedColor(color) ? [{
      name: "u_borderColor_".concat(i + 1),
      type: "vec4",
      value: colorToVec4(color)
    }] : [];
  });

  // Generate attributes for attribute-based colors/sizes
  var attributes = [].concat(_toConsumableArray(borders.flatMap(function (_ref6, i) {
    var color = _ref6.color;
    return isAttributeColor(color) ? [{
      name: "borderColor_".concat(i + 1),
      size: 4,
      type: UNSIGNED_BYTE,
      normalized: true,
      source: color.attribute,
      defaultValue: color["default"]
    }] : [];
  })), _toConsumableArray(borders.flatMap(function (_ref7, i) {
    var size = _ref7.size;
    return isAttributeSize(size) ? [{
      name: "borderSize_".concat(i + 1),
      size: 1,
      type: FLOAT,
      source: size.attribute,
      defaultValue: size["default"]
    }] : [];
  })));
  return {
    name: "border",
    uniforms: uniforms,
    attributes: attributes,
    glsl: generateBorderGLSL(borders)
  };
}

/**
 * Sigma.js Node Border Types
 * ==========================
 *
 * Type definitions for the node border layer and program.
 *
 * @module
 */

/**
 * Mode for border size specification.
 * - "relative": Size is a fraction of the shape size (0.0 to 1.0)
 * - "pixels": Size is in screen pixels
 */

var DEFAULT_BORDER_SIZE_MODE = "relative";

/**
 * Schema for the border layer.
 *
 * Each border in the array specifies:
 * - size: Border thickness (number or attribute reference)
 * - color: Border color (CSS color or attribute reference)
 * - mode: How to interpret size ("relative" = fraction of shape, "pixels" = screen pixels)
 * - fill: If true, this border fills remaining space (size is ignored)
 */
var borderSchema = {
  borders: arrayProp({
    size: numberProp(0.1, {
      variable: true
    }),
    color: colorProp("#000000", {
      variable: true
    }),
    mode: enumProp(["relative", "pixels"], "relative"),
    fill: booleanProp(false)
  })
};

/**
 * Options for the layerBorder() function.
 * Derived from the borderSchema.
 */

/**
 * Options for creating a node border program.
 */

/**
 * Default border configuration: 10% outer border with fill.
 */
var DEFAULT_BORDERS = [{
  size: {
    attribute: "borderSize",
    "default": 0.1
  },
  color: {
    attribute: "borderColor"
  },
  mode: "relative"
}, {
  size: 0,
  color: {
    attribute: "color"
  },
  fill: true
}];

/**
 * Default border program options.
 */
var DEFAULT_CREATE_NODE_BORDER_OPTIONS = {
  borders: DEFAULT_BORDERS,
  shapeFactory: sdfCircle
};

/**
 * Default color when attribute is not found.
 */
var DEFAULT_COLOR = "#000000";

window.SigmaNodeBorder = { DEFAULT_BORDERS, DEFAULT_BORDER_SIZE_MODE, DEFAULT_COLOR, DEFAULT_CREATE_NODE_BORDER_OPTIONS, borderSchema, layerBorder };
})();
