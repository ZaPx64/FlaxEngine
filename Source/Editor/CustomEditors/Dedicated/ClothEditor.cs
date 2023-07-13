// Copyright (c) 2012-2023 Wojciech Figat. All rights reserved.

using FlaxEditor.Gizmo;
using FlaxEditor.Scripting;
using FlaxEngine;
using FlaxEngine.GUI;
using FlaxEngine.Tools;

namespace FlaxEditor.CustomEditors.Dedicated
{
    /// <summary>
    /// Custom editor for <see cref="Cloth"/>.
    /// </summary>
    /// <seealso cref="ActorEditor" />
    [CustomEditor(typeof(Cloth)), DefaultEditor]
    class ClothEditor : ActorEditor
    {
        private ClothPaintingGizmoMode _gizmoMode;
        private Viewport.Modes.EditorGizmoMode _prevMode;

        /// <inheritdoc />
        public override void Initialize(LayoutElementsContainer layout)
        {
            base.Initialize(layout);

            if (Values.Count != 1)
                return;

            // Add gizmo painting mode to the viewport
            var owner = Presenter.Owner;
            if (owner == null)
                return;
            var gizmoOwner = owner as IGizmoOwner ?? owner.PresenterViewport as IGizmoOwner;
            if (gizmoOwner == null)
                return;
            var gizmos = gizmoOwner.Gizmos;
            _gizmoMode = new ClothPaintingGizmoMode();
            gizmos.AddMode(_gizmoMode);
            _prevMode = gizmos.ActiveMode;
            gizmos.ActiveMode = _gizmoMode;
            _gizmoMode.Gizmo.SetPaintCloth((Cloth)Values[0]);

            // Insert gizmo mode options to properties editing
            var paintGroup = layout.Group("Cloth Painting");
            var paintValue = new ReadOnlyValueContainer(new ScriptType(typeof(ClothPaintingGizmoMode)), _gizmoMode);
            paintGroup.Object(paintValue);
            {
                var grid = paintGroup.CustomContainer<UniformGridPanel>();
                var gridControl = grid.CustomControl;
                gridControl.ClipChildren = false;
                gridControl.Height = Button.DefaultHeight;
                gridControl.SlotsHorizontally = 2;
                gridControl.SlotsVertically = 1;
                grid.Button("Fill", "Fills the cloth particles with given paint value.").Button.Clicked += _gizmoMode.Gizmo.Fill;
                grid.Button("Reset", "Clears the cloth particles paint.").Button.Clicked += _gizmoMode.Gizmo.Reset;
            }
        }

        /// <inheritdoc />
        protected override void Deinitialize()
        {
            // Cleanup gizmos
            if (_gizmoMode != null)
            {
                var gizmos = _gizmoMode.Owner.Gizmos;
                if (gizmos.ActiveMode == _gizmoMode)
                    gizmos.ActiveMode = _prevMode;
                gizmos.RemoveMode(_gizmoMode);
                _gizmoMode.Dispose();
                _gizmoMode = null;
            }
            _prevMode = null;

            base.Deinitialize();
        }
    }
}
